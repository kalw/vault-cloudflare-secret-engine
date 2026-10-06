// Package integration runs the compiled plugin inside a real Vault server.
//
// The tests are skipped unless VAULT_BIN points at a Vault binary. They build
// the plugin, start `vault server -dev` with a plugin directory, register the
// plugin in the catalog (sha256 + semver version, as an operator would), mount
// it and drive every endpoint against a fake Cloudflare API, which the plugin
// reaches through the CLOUDFLARE_API_BASE_URL environment variable injected at
// catalog registration.
//
//	VAULT_BIN=$(which vault) go test ./integration -v
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	pluginName    = "vault-cloudflare-secret-engine"
	pluginVersion = "v1.2.3"
	rootToken     = "root"
	accountID     = "0123456789abcdef0123456789abcdef"

	pgDNSReadID  = "11111111111111111111111111111111"
	pgZoneReadID = "22222222222222222222222222222222"
)

var (
	tokensPath = regexp.MustCompile(`^/accounts/([0-9a-f]{32})/tokens$`)
	tokenPath  = regexp.MustCompile(`^/accounts/([0-9a-f]{32})/tokens/([0-9a-f]{32})$`)
	rollPath   = regexp.MustCompile(`^/accounts/([0-9a-f]{32})/tokens/([0-9a-f]{32})/value$`)
)

// fakeCloudflare implements the token endpoints the engine uses: permission
// group listing, verify, create, delete and value roll. It authenticates every
// call against the current parent value and records created tokens so tests can
// assert revocation.
type fakeCloudflare struct {
	*httptest.Server

	mu          sync.Mutex
	parentID    string
	parentValue string          // current live parent token value
	active      map[string]bool // minted token id -> not revoked yet
	nextID      int
	lastCreate  map[string]any // body of the last create call
}

func newFakeCloudflare(t *testing.T) *fakeCloudflare {
	t.Helper()

	f := &fakeCloudflare{
		parentID:    "ffffffffffffffffffffffffffffffff",
		parentValue: "parent-secret-v1",
		active:      map[string]bool{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.Close)

	return f
}

func envelope(w http.ResponseWriter, status int, result string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	ok := "true"
	if status >= 400 {
		ok = "false"
	}
	fmt.Fprintf(w, `{"success":%s,"errors":[],"result":%s}`, ok, result)
}

func (f *fakeCloudflare) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer != f.parentValue {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"invalid token"}]}`)

		return
	}

	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tokens/permission_groups"):
		envelope(w, http.StatusOK, fmt.Sprintf(
			`[{"id":%q,"name":"DNS Read"},{"id":%q,"name":"Zone Read"}]`, pgDNSReadID, pgZoneReadID))
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tokens/verify"):
		envelope(w, http.StatusOK, fmt.Sprintf(`{"id":%q,"status":"active"}`, f.parentID))
	case r.Method == http.MethodPut && rollPath.MatchString(r.URL.Path):
		f.parentValue += "-rolled"
		envelope(w, http.StatusOK, fmt.Sprintf("%q", f.parentValue))
	case r.Method == http.MethodPost && tokensPath.MatchString(r.URL.Path):
		body := map[string]any{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		f.lastCreate = body
		f.nextID++
		id := fmt.Sprintf("%032x", 0xabc0+f.nextID)
		f.active[id] = true
		envelope(w, http.StatusCreated, fmt.Sprintf(
			`{"id":%q,"name":%q,"value":"minted-%d"}`, id, body["name"], f.nextID))
	case r.Method == http.MethodDelete && tokenPath.MatchString(r.URL.Path):
		id := tokenPath.FindStringSubmatch(r.URL.Path)[2]
		if !f.active[id] {
			envelope(w, http.StatusNotFound, "null")

			return
		}
		f.active[id] = false
		envelope(w, http.StatusOK, "null")
	default:
		envelope(w, http.StatusNotFound, "null")
	}
}

func (f *fakeCloudflare) activeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0
	for _, ok := range f.active {
		if ok {
			n++
		}
	}

	return n
}

func (f *fakeCloudflare) isActive(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.active[id]
}

func (f *fakeCloudflare) liveParent() string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.parentValue
}

func (f *fakeCloudflare) last() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.lastCreate
}

// buildPlugin compiles the plugin with pluginVersion stamped in and returns the
// plugin directory and the binary sha256.
func buildPlugin(t *testing.T) (string, string) {
	t.Helper()

	dir, err := filepath.EvalSymlinks(t.TempDir()) // Vault rejects symlinked plugin dirs (macOS /var)
	if err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(dir, pluginName)
	cmd := exec.Command("go", "build", "-o", bin,
		"-ldflags", "-X main.version="+strings.TrimPrefix(pluginVersion, "v"),
		"../cmd/vault-cloudflare-secret-engine")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building plugin: %v\n%s", err, out)
	}

	content, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)

	return dir, hex.EncodeToString(sum[:])
}

func freeAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	return addr
}

// startVault runs a dev server whose plugin_directory is pluginDir, without
// auto-registering anything so the test exercises the real catalog flow.
func startVault(t *testing.T, vaultBin, pluginDir string) *api.Client {
	t.Helper()

	cfg := filepath.Join(t.TempDir(), "vault.hcl")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("plugin_directory = %q\n", pluginDir)), 0o600); err != nil {
		t.Fatal(err)
	}

	addr := freeAddr(t)
	logFile, err := os.Create(filepath.Join(t.TempDir(), "vault.log"))
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(vaultBin, "server", "-dev",
		"-dev-root-token-id="+rootToken,
		"-dev-listen-address="+addr,
		"-config="+cfg,
		"-log-level=debug")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "VAULT_DISABLE_MLOCK=true", "SKIP_SETCAP=true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			logs, _ := os.ReadFile(logFile.Name())
			t.Logf("vault server logs:\n%s", logs)
		}
	})

	conf := api.DefaultConfig()
	conf.Address = "http://" + addr
	client, err := api.NewClient(conf)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(rootToken)

	deadline := time.Now().Add(30 * time.Second)
	for {
		h, err := client.Sys().Health()
		if err == nil && h.Initialized && !h.Sealed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("vault dev server did not become ready")
		}
		time.Sleep(200 * time.Millisecond)
	}

	return client
}

func fatalIf(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

//nolint:gocyclo,maintidx
func TestVault(t *testing.T) {
	vaultBin := os.Getenv("VAULT_BIN")
	if vaultBin == "" {
		t.Skip("VAULT_BIN not set; skipping Vault integration tests")
	}
	out, err := exec.Command(vaultBin, "version").CombinedOutput()
	fatalIf(t, err, "vault version")
	t.Logf("running against %s", strings.TrimSpace(string(out)))

	ctx := context.Background()
	fake := newFakeCloudflare(t)
	pluginDir, sha := buildPlugin(t)
	client := startVault(t, vaultBin, pluginDir)
	sys := client.Sys()
	logical := client.Logical()

	register := func(version string) error {
		return sys.RegisterPluginWithContext(ctx, &api.RegisterPluginInput{
			Name:    pluginName,
			Type:    api.PluginTypeSecrets,
			Command: pluginName,
			SHA256:  sha,
			Version: version,
			// Point the plugin at the fake API; operator-controlled, injected
			// into the plugin process by Vault.
			Env: []string{"CLOUDFLARE_API_BASE_URL=" + fake.URL},
		})
	}

	t.Run("binary reports its version", func(t *testing.T) {
		out, err := exec.Command(filepath.Join(pluginDir, pluginName), "--version").CombinedOutput()
		fatalIf(t, err, "plugin --version")
		if !strings.Contains(string(out), strings.TrimPrefix(pluginVersion, "v")) {
			t.Fatalf("--version output %q does not contain %s", out, pluginVersion)
		}
	})

	t.Run("registering with a mismatched version is rejected", func(t *testing.T) {
		err := register("v9.9.9")
		if err == nil || !strings.Contains(err.Error(), "version mismatch") {
			t.Fatalf("expected a version-mismatch rejection, got %v", err)
		}
	})

	t.Run("register versioned plugin and mount pinned to it", func(t *testing.T) {
		fatalIf(t, register(pluginVersion), "register")

		p, err := sys.GetPluginWithContext(ctx, &api.GetPluginInput{
			Name: pluginName, Type: api.PluginTypeSecrets, Version: pluginVersion,
		})
		fatalIf(t, err, "get plugin")
		if p.Version != pluginVersion || p.SHA256 != sha {
			t.Fatalf("catalog entry mismatch: %+v", p)
		}

		fatalIf(t, sys.MountWithContext(ctx, "cloudflare", &api.MountInput{
			Type:   pluginName,
			Config: api.MountConfigInput{PluginVersion: pluginVersion},
		}), "mount")

		m, err := sys.GetMountWithContext(ctx, "cloudflare")
		fatalIf(t, err, "get mount")
		if m.RunningVersion != pluginVersion || m.RunningSha256 != sha {
			t.Fatalf("mount running version/sha mismatch: %+v", m)
		}
	})

	t.Run("config write, redaction on read, account id validation", func(t *testing.T) {
		_, err := logical.Write("cloudflare/config", map[string]any{
			"cloudflare_account_id": "../user", "cloudflare_api_token": "x",
		})
		if err == nil || !strings.Contains(err.Error(), "32-character hex") {
			t.Fatalf("expected account id rejection, got %v", err)
		}

		_, err = logical.Write("cloudflare/config", map[string]any{
			"cloudflare_account_id": accountID,
			"cloudflare_api_token":  fake.liveParent(),
			"max_ttl":               "2h",
			"ttl":                   "10m",
		})
		fatalIf(t, err, "config write")

		resp, err := logical.Read("cloudflare/config")
		fatalIf(t, err, "config read")
		if resp.Data["cloudflare_account_id"] != accountID {
			t.Fatalf("account id not returned: %v", resp.Data)
		}
		got, _ := resp.Data["cloudflare_api_token"].(string)
		if strings.Contains(got, "parent-secret") || got != "***redacted***" {
			t.Fatalf("token not fully redacted on read: %q", got)
		}
	})

	t.Run("role validation and CRUD", func(t *testing.T) {
		_, err := logical.Write("cloudflare/role/bad", map[string]any{
			"policies": `[{"permission_groups":[{"id":"x"}],"resources":{"a":"*"},"effect":"maybe"}]`,
		})
		if err == nil || !strings.Contains(err.Error(), `effect must be`) {
			t.Fatalf("expected effect rejection, got %v", err)
		}

		_, err = logical.Write("cloudflare/role/bad", map[string]any{
			"policies":      fmt.Sprintf(`[{"permission_groups":[{"id":%q}],"resources":{"a":"*"}}]`, pgDNSReadID),
			"request_ip_in": "not-a-cidr",
		})
		if err == nil || !strings.Contains(err.Error(), "not a valid IP") {
			t.Fatalf("expected CIDR rejection, got %v", err)
		}

		// One group by id, one by (case-insensitive) name to exercise live resolution.
		_, err = logical.Write("cloudflare/role/dns", map[string]any{
			"policies": fmt.Sprintf(
				`[{"permission_groups":[{"id":%q},{"name":"zone read"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]`,
				pgDNSReadID, accountID),
			"ttl": "5m",
		})
		fatalIf(t, err, "role write")

		resp, err := logical.List("cloudflare/role")
		fatalIf(t, err, "role list")
		keys := fmt.Sprintf("%v", resp.Data["keys"])
		if !strings.Contains(keys, "dns") {
			t.Fatalf("role listing missing dns: %v", keys)
		}
	})

	var mintedID string

	t.Run("creds: mint resolves names, lease revoke deletes in cloudflare", func(t *testing.T) {
		resp, err := logical.Read("cloudflare/creds/dns")
		fatalIf(t, err, "creds read")
		if resp.LeaseID == "" || !resp.Renewable {
			t.Fatalf("expected a renewable lease, got %+v", resp)
		}
		if resp.LeaseDuration != 300 {
			t.Fatalf("lease duration = %d, want role ttl 300", resp.LeaseDuration)
		}
		mintedID, _ = resp.Data["token_id"].(string)
		if mintedID == "" || resp.Data["token"] == "" {
			t.Fatalf("missing token data: %v", resp.Data)
		}

		// The create request must carry resolved IDs only.
		body, _ := json.Marshal(fake.last()["policies"])
		if !strings.Contains(string(body), pgZoneReadID) || strings.Contains(string(body), "Zone Read") {
			t.Fatalf("permission group name was not resolved to an id: %s", body)
		}

		fatalIf(t, sys.RevokeWithContext(ctx, resp.LeaseID), "lease revoke")
		if fake.isActive(mintedID) {
			t.Fatalf("token %s still active in cloudflare after lease revoke", mintedID)
		}
	})

	t.Run("lease expiry revokes automatically", func(t *testing.T) {
		_, err := logical.Write("cloudflare/role/short", map[string]any{
			"policies": fmt.Sprintf(`[{"permission_groups":[{"id":%q}],"resources":{"a":"*"}}]`, pgDNSReadID),
			"ttl":      "3s",
		})
		fatalIf(t, err, "role write")

		resp, err := logical.Read("cloudflare/creds/short")
		fatalIf(t, err, "creds read")
		id, _ := resp.Data["token_id"].(string)

		deadline := time.Now().Add(30 * time.Second)
		for fake.isActive(id) {
			if time.Now().After(deadline) {
				t.Fatalf("token %s not revoked after lease expiry", id)
			}
			time.Sleep(250 * time.Millisecond)
		}
	})

	t.Run("renew honors the increment, capped by the issuance max_ttl", func(t *testing.T) {
		resp, err := logical.Read("cloudflare/creds/dns")
		fatalIf(t, err, "creds read")

		renewed, err := sys.RenewWithContext(ctx, resp.LeaseID, 3600)
		fatalIf(t, err, "renew")
		if renewed.LeaseDuration != 3600 {
			t.Fatalf("renewed lease duration = %d, want the 3600s increment", renewed.LeaseDuration)
		}

		// An increment beyond max_ttl (2h at issuance) must be capped: the
		// lease can never outlive the Cloudflare-side expires_on backstop.
		renewed, err = sys.RenewWithContext(ctx, resp.LeaseID, 5*3600)
		fatalIf(t, err, "renew beyond cap")
		if renewed.LeaseDuration > 2*3600 {
			t.Fatalf("renewed lease duration = %d, exceeds the 7200s max_ttl cap", renewed.LeaseDuration)
		}
	})

	t.Run("rotate-root: old parent dies, minting continues on the new value", func(t *testing.T) {
		before := fake.liveParent()

		resp, err := logical.Write("cloudflare/config/rotate-root", map[string]any{"token_type": "account"})
		fatalIf(t, err, "rotate-root")
		if resp.Data["rotated"] != true {
			t.Fatalf("unexpected rotate response: %v", resp.Data)
		}
		for _, v := range resp.Data {
			if s, ok := v.(string); ok && strings.Contains(s, fake.liveParent()) {
				t.Fatalf("rotate-root leaked the new parent value")
			}
		}
		if fake.liveParent() == before {
			t.Fatalf("parent value did not roll")
		}

		// The fake 401s any stale bearer, so a successful mint proves the
		// plugin persisted and now uses the rolled value.
		if _, err := logical.Read("cloudflare/creds/dns"); err != nil {
			t.Fatalf("mint after rotation failed: %v", err)
		}
	})

	t.Run("multiplexed second mount is isolated", func(t *testing.T) {
		fatalIf(t, sys.MountWithContext(ctx, "cloudflare-b", &api.MountInput{
			Type:   pluginName,
			Config: api.MountConfigInput{PluginVersion: pluginVersion},
		}), "second mount")

		resp, err := logical.Read("cloudflare-b/config")
		fatalIf(t, err, "config read on second mount")
		if resp != nil {
			t.Fatalf("second mount sees the first mount's config: %v", resp.Data)
		}

		_, err = logical.Read("cloudflare-b/creds/dns")
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing role on isolated mount, got %v", err)
		}
	})

	t.Run("plugin reload keeps mounts working", func(t *testing.T) {
		_, err := sys.ReloadPluginWithContext(ctx, &api.ReloadPluginInput{Plugin: pluginName})
		fatalIf(t, err, "reload")

		deadline := time.Now().Add(15 * time.Second)
		for {
			if _, err = logical.Read("cloudflare/creds/dns"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("mint after reload failed: %v", err)
			}
			time.Sleep(250 * time.Millisecond)
		}
	})

	t.Run("path help and openapi", func(t *testing.T) {
		resp, err := client.Logical().ReadWithData("cloudflare/config", map[string][]string{"help": {"1"}})
		fatalIf(t, err, "path-help")
		help, _ := resp.Data["help"].(string)
		if !strings.Contains(help, "Cloudflare") {
			t.Fatalf("unexpected help output: %q", help)
		}

		r := client.NewRequest(http.MethodGet, "/v1/sys/internal/specs/openapi")
		raw, err := client.RawRequestWithContext(ctx, r) //nolint:staticcheck
		fatalIf(t, err, "openapi")
		defer raw.Body.Close()

		var spec struct {
			Paths map[string]any `json:"paths"`
		}
		fatalIf(t, json.NewDecoder(raw.Body).Decode(&spec), "decode openapi")
		for _, p := range []string{"/cloudflare/config", "/cloudflare/creds/{name}", "/cloudflare/config/rotate-root"} {
			if _, ok := spec.Paths[p]; !ok {
				t.Fatalf("openapi is missing %s", p)
			}
		}
	})

	t.Run("disabling the mounts revokes every outstanding token", func(t *testing.T) {
		if fake.activeCount() == 0 {
			t.Fatal("expected outstanding tokens before unmount")
		}
		for _, mount := range []string{"cloudflare", "cloudflare-b"} {
			fatalIf(t, sys.UnmountWithContext(ctx, mount), "unmount "+mount)
		}
		if n := fake.activeCount(); n != 0 {
			t.Fatalf("%d tokens left in cloudflare after unmount", n)
		}
	})
}
