package cloudflaresecrets

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestAcceptance_TokenLifecycle exercises the full lifecycle against the live
// Cloudflare API: configure the backend, create a role, mint a token, then
// revoke it. It is skipped unless VAULT_ACC is set.
//
// Required environment:
//   - VAULT_ACC=1
//   - CLOUDFLARE_ACCOUNT_ID    account that owns the generated tokens
//   - CLOUDFLARE_API_TOKEN     parent token with the "API Tokens Write" permission
//
// Optional environment:
//   - CLOUDFLARE_TEST_POLICIES  full policies JSON to use for the role.
//     Defaults to a minimal, low-privilege account-scoped policy
//     ("Account Settings Read" on the configured account).
func TestAcceptance_TokenLifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test; set VAULT_ACC=1 to run")
	}

	accountID := requireEnv(t, "CLOUDFLARE_ACCOUNT_ID")
	apiToken := requireEnv(t, "CLOUDFLARE_API_TOKEN")

	policies := os.Getenv("CLOUDFLARE_TEST_POLICIES")
	if policies == "" {
		policies = fmt.Sprintf(
			`[{"effect":"allow","permission_groups":[{"name":"Account Settings Read"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]`,
			accountID,
		)
	}

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b, err := Factory(ctx, conf)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// 1. Configure the backend.
	mustWrite(t, ctx, b, storage, "config", map[string]interface{}{
		"cloudflare_account_id": accountID,
		"cloudflare_api_token":  apiToken,
		"ttl":                   "5m",
		"max_ttl":               "10m",
	})

	// 2. Create a role.
	mustWrite(t, ctx, b, storage, "role/acc-test", map[string]interface{}{
		"token_type": tokenTypeAccount,
		"policies":   policies,
	})

	// 3. Mint a token from the role.
	credsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/acc-test",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, credsReq)
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
	t.Logf("minted cloudflare token id=%s", tokenID)

	// 4. Revoke the lease; the Cloudflare token must be deleted.
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/acc-test",
		Storage:   storage,
		Secret:    resp.Secret,
	}
	revResp, err := b.HandleRequest(ctx, revokeReq)
	if err != nil || (revResp != nil && revResp.IsError()) {
		t.Fatalf("revoke: err=%v resp=%v", err, revResp)
	}

	// 5. Confirm the token is gone: deleting it again should fail.
	client := newCloudflareClient(accountID, apiToken)
	scope := tokenScope{Type: tokenTypeAccount, AccountID: accountID}
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
