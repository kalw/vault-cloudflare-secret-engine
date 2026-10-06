package cloudflaresecrets

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// TestRotateRootAccount verifies config/rotate-root discovers the parent
// token's ID via verify, rolls its value, persists the new value, and never
// returns the plaintext. [H5]
func TestRotateRootAccount(t *testing.T) {
	const (
		oldValue = "v1.0-OLD-PARENT-VALUE"
		newValue = "v1.0-NEW-ROLLED-VALUE"
		tokID    = "abcdef0123456789abcdef0123456789"
	)
	var verifyCalls, rollCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tokens/verify"):
			atomic.AddInt32(&verifyCalls, 1)
			// The verify call must authenticate with the current parent token.
			if got := r.Header.Get("Authorization"); got != "Bearer "+oldValue {
				t.Errorf("verify used %q, want bearer old value", got)
			}
			writeEnvelope(w, http.StatusOK,
				`{"success":true,"result":{"id":"`+tokID+`","status":"active"}}`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/tokens/"+tokID+"/value"):
			atomic.AddInt32(&rollCalls, 1)
			writeEnvelope(w, http.StatusOK, `{"success":true,"result":"`+newValue+`"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeEnvelope(w, http.StatusNotFound, `{"success":false,"errors":[{"code":1,"message":"no"}]}`)
		}
	}))
	defer srv.Close()

	b, storage := newTestBackendWithAPI(t, srv.URL)
	ctx := context.Background()

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"cloudflare_account_id": testAccountID,
			"cloudflare_api_token":  oldValue,
		},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
		Data:      map[string]interface{}{"token_type": tokenTypeAccount},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}
	if resp.Data["token_id"] != tokID || resp.Data["rotated"] != true {
		t.Fatalf("unexpected response data: %#v", resp.Data)
	}
	// The plaintext new value must never be returned.
	for k, v := range resp.Data {
		if s, ok := v.(string); ok && strings.Contains(s, newValue) {
			t.Fatalf("response field %q leaked the new token value", k)
		}
	}
	if atomic.LoadInt32(&verifyCalls) != 1 || atomic.LoadInt32(&rollCalls) != 1 {
		t.Fatalf("expected 1 verify + 1 roll, got %d verify %d roll", verifyCalls, rollCalls)
	}

	// The rolled value must be persisted so future operations use it.
	cfg, err := getConfig(ctx, storage)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.APIToken != newValue {
		t.Fatalf("config still holds the old token value after rotation")
	}
}

// TestRotateRootUnconfiguredContext rejects rotating a context that has no
// configured credential.
func TestRotateRootUnconfiguredContext(t *testing.T) {
	b, storage := newTestBackendWithAPI(t, "http://127.0.0.1:0")
	ctx := context.Background()

	// Configure only the account context.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"cloudflare_account_id": testAccountID,
			"cloudflare_api_token":  "v",
		},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
		Data:      map[string]interface{}{"token_type": tokenTypeUser},
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error rotating an unconfigured user context, got %v", resp)
	}
}

// failingStorage wraps a logical.Storage and fails Put for keys with a given
// prefix, to exercise rotation's storage-failure windows.
type failingStorage struct {
	logical.Storage
	failPutPrefix string
}

func (f *failingStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, f.failPutPrefix) {
		return errInjectedPut
	}
	return f.Storage.Put(ctx, entry)
}

var errInjectedPut = errors.New("storage put failed (injected)")

// rotateFakeCF is a stateful fake for the rotation endpoints: verify answers
// with the token ID matching the presented bearer value, roll flips the live
// value, and every call is counted.
type rotateFakeCF struct {
	t                      *testing.T
	tokID                  string
	mu                     sync.Mutex
	liveValue              string
	verifyCalls, rollCalls int
}

func (f *rotateFakeCF) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tokens/verify"):
		f.verifyCalls++
		if bearer != f.liveValue {
			writeEnvelope(w, http.StatusUnauthorized, `{"success":false,"errors":[{"code":10000,"message":"invalid token"}]}`)
			return
		}
		writeEnvelope(w, http.StatusOK, `{"success":true,"result":{"id":"`+f.tokID+`","status":"active"}}`)
	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/tokens/"+f.tokID+"/value"):
		f.rollCalls++
		if bearer != f.liveValue {
			writeEnvelope(w, http.StatusUnauthorized, `{"success":false,"errors":[{"code":10000,"message":"invalid token"}]}`)
			return
		}
		f.liveValue = f.liveValue + "-rolled"
		writeEnvelope(w, http.StatusOK, `{"success":true,"result":"`+f.liveValue+`"}`)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		writeEnvelope(w, http.StatusNotFound, `{"success":false,"errors":[{"code":1,"message":"no"}]}`)
	}
}

func newRotateEnv(t *testing.T, oldValue, tokID string) (*rotateFakeCF, logical.Backend, logical.Storage) {
	t.Helper()

	fake := &rotateFakeCF{t: t, tokID: tokID, liveValue: oldValue}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)

	b, storage := newTestBackendWithAPI(t, srv.URL)
	mustWrite(t, context.Background(), b, storage, "config", map[string]interface{}{
		"cloudflare_account_id": testAccountID,
		"cloudflare_api_token":  oldValue,
	})
	return fake, b, storage
}

func rotate(ctx context.Context, b logical.Backend, s logical.Storage) (*logical.Response, error) {
	return b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
		Data:      map[string]interface{}{"token_type": tokenTypeAccount},
	})
}

// TestRotateRootWALPreflight: if storage cannot even record the WAL, the
// rotation aborts BEFORE the Cloudflare-side roll, so nothing is invalidated.
func TestRotateRootWALPreflight(t *testing.T) {
	const tokID = "abcdef0123456789abcdef0123456789"
	fake, b, storage := newRotateEnv(t, "OLD", tokID)
	ctx := context.Background()

	_, err := rotate(ctx, b, &failingStorage{Storage: storage, failPutPrefix: "wal/"})
	if err == nil || !strings.Contains(err.Error(), "nothing was invalidated") {
		t.Fatalf("expected preflight abort, got %v", err)
	}
	if fake.rollCalls != 0 {
		t.Fatalf("token was rolled despite the preflight failure")
	}
	if cfg, _ := getConfig(ctx, storage); cfg.APIToken != "OLD" {
		t.Fatalf("config changed on an aborted rotation")
	}
}

// TestRotateRootPersistFailureLeavesWAL: the roll happened but the new value
// could not be stored - the error explains recovery, the WAL survives, and the
// rollback pass diagnoses the stranded credential loudly (keeps the WAL).
func TestRotateRootPersistFailureLeavesWAL(t *testing.T) {
	const tokID = "abcdef0123456789abcdef0123456789"
	fake, b, storage := newRotateEnv(t, "OLD", tokID)
	ctx := context.Background()

	_, err := rotate(ctx, b, &failingStorage{Storage: storage, failPutPrefix: configStoragePath})
	if err == nil || !strings.Contains(err.Error(), "mint a fresh parent token") {
		t.Fatalf("expected a recovery-path error, got %v", err)
	}
	if fake.rollCalls != 1 {
		t.Fatalf("expected exactly one roll, got %d", fake.rollCalls)
	}

	walIDs, err := framework.ListWAL(ctx, storage)
	if err != nil || len(walIDs) != 1 {
		t.Fatalf("expected the rotation WAL to survive, got %v (err=%v)", walIDs, err)
	}
	entry, err := framework.GetWAL(ctx, storage, walIDs[0])
	if err != nil || entry.Kind != walKindRotateRoot {
		t.Fatalf("unexpected WAL entry %#v (err=%v)", entry, err)
	}

	// The rollback pass must detect the stranded credential: the stored value
	// ("OLD") no longer authenticates because Cloudflare holds "OLD-rolled".
	cb, _ := b.(*cloudflareBackend)
	rbErr := cb.walRollback(ctx, &logical.Request{Storage: storage}, entry.Kind, entry.Data)
	if rbErr == nil || !strings.Contains(rbErr.Error(), "no longer authenticates") {
		t.Fatalf("rollback should keep flagging the stranded credential, got %v", rbErr)
	}
}

// TestRotateRootWALRollbackHealthy: a leftover WAL from a rotation that in fact
// completed (stored credential authenticates) is reaped silently.
func TestRotateRootWALRollbackHealthy(t *testing.T) {
	const tokID = "abcdef0123456789abcdef0123456789"
	fake, b, storage := newRotateEnv(t, "OLD", tokID)
	ctx := context.Background()

	if resp, err := rotate(ctx, b, storage); err != nil || resp.IsError() {
		t.Fatalf("rotate: err=%v resp=%v", err, resp)
	}
	if ids, _ := framework.ListWAL(ctx, storage); len(ids) != 0 {
		t.Fatalf("happy-path rotation left a WAL behind: %v", ids)
	}
	if cfg, _ := getConfig(ctx, storage); cfg.APIToken != fake.liveValue {
		t.Fatalf("persisted value does not match Cloudflare's live value")
	}

	// Simulate a WAL that survived a completed rotation (e.g. DeleteWAL lost):
	// rollback must verify the healthy state and return nil so it gets reaped.
	cb, _ := b.(*cloudflareBackend)
	err := cb.walRollback(ctx, &logical.Request{Storage: storage}, walKindRotateRoot,
		map[string]interface{}{"token_type": tokenTypeAccount, "account_id": testAccountID, "token_id": tokID})
	if err != nil {
		t.Fatalf("rollback on a healthy state must be silent, got %v", err)
	}
}
