package cloudflaresecrets

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestAcceptance_TokenIPRestriction mints an account-context token from a role
// carrying request_ip_in/_not_in and confirms Cloudflare persisted the
// condition.request_ip on the resulting token. Skipped unless VAULT_ACC is set.
func TestAcceptance_TokenIPRestriction(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test; set VAULT_ACC=1 to run")
	}
	accountID := requireEnv(t, "CLOUDFLARE_ACCOUNT_ID")
	apiToken := requireEnv(t, "CLOUDFLARE_API_TOKEN")

	const allowCIDR = "203.0.113.0/24"
	const denyCIDR = "198.51.100.7/32"

	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b, err := Factory(ctx, conf)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	mustWrite(t, ctx, b, storage, "config", map[string]interface{}{
		"cloudflare_account_id": accountID,
		"cloudflare_api_token":  apiToken,
		"ttl":                   "5m",
		"max_ttl":               "10m",
	})
	mustWrite(t, ctx, b, storage, "role/ip-test", map[string]interface{}{
		"token_type": tokenTypeAccount,
		"policies": fmt.Sprintf(
			`[{"effect":"allow","permission_groups":[{"name":"Account Settings Read"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]`,
			accountID),
		"request_ip_in":     allowCIDR,
		"request_ip_not_in": denyCIDR,
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/ip-test",
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("creds read: err=%v resp=%v", err, resp)
	}
	tokenID, _ := resp.Data["token_id"].(string)
	if tokenID == "" {
		t.Fatal("no token_id returned")
	}
	t.Logf("minted IP-restricted token id=%s", tokenID)

	// Fetch the token from Cloudflare and confirm the condition was stored.
	client := newCloudflareClient(apiToken)
	var td struct {
		Condition *tokenCondition `json:"condition"`
	}
	if err := client.do(ctx, http.MethodGet,
		fmt.Sprintf("/accounts/%s/tokens/%s", accountID, tokenID), nil, &td); err != nil {
		t.Fatalf("get token details: %v", err)
	}
	if td.Condition == nil || td.Condition.RequestIP == nil {
		t.Fatalf("token has no condition.request_ip: %+v", td.Condition)
	}
	if !sliceContains(td.Condition.RequestIP.In, allowCIDR) {
		t.Fatalf("request_ip.in = %v, want to contain %s", td.Condition.RequestIP.In, allowCIDR)
	}
	if !sliceContains(td.Condition.RequestIP.NotIn, denyCIDR) {
		t.Fatalf("request_ip.not_in = %v, want to contain %s", td.Condition.RequestIP.NotIn, denyCIDR)
	}

	// Clean up: revoke the lease, which deletes the token.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/ip-test",
		Storage:   storage,
		Secret:    resp.Secret,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
