package cloudflaresecrets

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestAcceptance_TokenLifecycle exercises the full lifecycle against the live
// Cloudflare API for each token context: configure the backend, create a role,
// mint a token, revoke it, and confirm it is deleted. Skipped unless VAULT_ACC
// is set.
//
// Required environment:
//   - VAULT_ACC=1
//   - CLOUDFLARE_ACCOUNT_ID    account that owns the generated tokens / resources
//
// Account-context case (token_type=account):
//   - CLOUDFLARE_API_TOKEN     parent token with "Account · API Tokens · Edit"
//   - CLOUDFLARE_TEST_POLICIES (optional) policies JSON override
//
// User-context case (token_type=user) — runs only when its parent token is set:
//   - CLOUDFLARE_USER_API_TOKEN      parent token with "User · API Tokens · Edit"
//   - CLOUDFLARE_USER_TEST_POLICIES  (optional) policies JSON override
//
// Both cases default to a minimal, low-privilege account-scoped policy
// ("Account Settings Read" on the configured account). Account-scoped
// permission groups are valid in user-owned tokens too, so the default works
// for both contexts.
func TestAcceptance_TokenLifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test; set VAULT_ACC=1 to run")
	}

	accountID := requireEnv(t, "CLOUDFLARE_ACCOUNT_ID")
	defaultPolicies := fmt.Sprintf(
		`[{"effect":"allow","permission_groups":[{"name":"Account Settings Read"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]`,
		accountID,
	)

	t.Run("account", func(t *testing.T) {
		apiToken := requireEnv(t, "CLOUDFLARE_API_TOKEN")
		runLifecycle(t, accountID, apiToken, tokenTypeAccount,
			envOr("CLOUDFLARE_TEST_POLICIES", defaultPolicies))
	})

	t.Run("user", func(t *testing.T) {
		apiToken := os.Getenv("CLOUDFLARE_USER_API_TOKEN")
		if apiToken == "" {
			t.Skip("set CLOUDFLARE_USER_API_TOKEN (a User API Token with \"User · API Tokens · Edit\") to run the user-scope case")
		}
		runLifecycle(t, accountID, apiToken, tokenTypeUser,
			envOr("CLOUDFLARE_USER_TEST_POLICIES", defaultPolicies))
	})
}

// runLifecycle drives one config → role → mint → revoke → verify cycle for the
// given token context using parentToken as the backend's parent credential.
func runLifecycle(t *testing.T, accountID, parentToken, tokenType, policies string) {
	t.Helper()
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b, err := Factory(ctx, conf)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// 1. Configure the backend with the parent credential for this context.
	configData := map[string]interface{}{
		"ttl":     "5m",
		"max_ttl": "10m",
	}
	switch tokenType {
	case tokenTypeUser:
		configData["cloudflare_user_api_token"] = parentToken
	default:
		configData["cloudflare_account_id"] = accountID
		configData["cloudflare_api_token"] = parentToken
	}
	mustWrite(t, ctx, b, storage, "config", configData)

	// 2. Create a role bound to this token context.
	mustWrite(t, ctx, b, storage, "role/acc-test", map[string]interface{}{
		"token_type": tokenType,
		"policies":   policies,
	})

	// 3. Mint a token from the role.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/acc-test",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("creds read: err=%v resp=%v", err, resp)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("creds read returned no secret")
	}

	token, _ := resp.Data["token"].(string)
	tokenID, _ := resp.Data["token_id"].(string)
	if token == "" || tokenID == "" {
		t.Fatalf("expected token and token_id, got token=%q token_id=%q", token, tokenID)
	}
	t.Logf("minted %s-context cloudflare token id=%s", tokenType, tokenID)

	// 4. Revoke the lease; the Cloudflare token must be deleted.
	revResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/acc-test",
		Storage:   storage,
		Secret:    resp.Secret,
	})
	if err != nil || (revResp != nil && revResp.IsError()) {
		t.Fatalf("revoke: err=%v resp=%v", err, revResp)
	}

	// 5. Confirm the token is gone: deleting it again should fail.
	client := newCloudflareClient(parentToken)
	scope := tokenScope{Type: tokenType, AccountID: accountID}
	if err := client.deleteToken(ctx, scope, tokenID); err == nil {
		t.Fatal("expected second delete to fail (token should already be revoked)")
	}
}

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s must be set for acceptance tests", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustWrite(t *testing.T, ctx context.Context, b logical.Backend, s logical.Storage, path string, data map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      path,
		Storage:   s,
		Data:      data,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write %s: err=%v resp=%v", path, err, resp)
	}
}
