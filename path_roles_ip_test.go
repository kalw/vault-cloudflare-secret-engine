package cloudflaresecrets

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestRoleRequestIPRoundTrip verifies the client-IP restriction is stored on the
// role and surfaced on read.
func TestRoleRequestIPRoundTrip(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b, err := Factory(ctx, conf)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/ip-test",
		Storage:   storage,
		Data: map[string]interface{}{
			"token_type":        tokenTypeAccount,
			"policies":          `[{"permission_groups":[{"name":"Account Settings Read"}],"resources":{"com.cloudflare.api.account.x":"*"}}]`,
			"request_ip_in":     "203.0.113.0/24,2001:db8::/32",
			"request_ip_not_in": "203.0.113.7/32",
		},
	}); err != nil {
		t.Fatalf("role write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/ip-test",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("role read: %v", err)
	}
	if got := resp.Data["request_ip_in"].([]string); !reflect.DeepEqual(got, []string{"203.0.113.0/24", "2001:db8::/32"}) {
		t.Fatalf("request_ip_in = %v", got)
	}
	if got := resp.Data["request_ip_not_in"].([]string); !reflect.DeepEqual(got, []string{"203.0.113.7/32"}) {
		t.Fatalf("request_ip_not_in = %v", got)
	}
}

// TestCreateTokenRequestConditionOmitted confirms the condition is omitted from
// the JSON body when no IP restriction is set, and present when it is.
func TestCreateTokenRequestConditionOmitted(t *testing.T) {
	noCond, _ := json.Marshal(&createTokenRequest{Name: "n", Policies: []policy{}})
	if got := string(noCond); contains(got, "condition") {
		t.Fatalf("expected no condition key, got %s", got)
	}

	withCond, _ := json.Marshal(&createTokenRequest{
		Name:      "n",
		Policies:  []policy{},
		Condition: &tokenCondition{RequestIP: &requestIP{In: []string{"203.0.113.0/24"}}},
	})
	if got := string(withCond); !contains(got, `"request_ip":{"in":["203.0.113.0/24"]}`) {
		t.Fatalf("expected request_ip in body, got %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
