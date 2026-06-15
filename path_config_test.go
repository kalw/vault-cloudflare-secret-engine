package cloudflaresecrets

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestParentTokenFor(t *testing.T) {
	cfg := &cloudflareConfig{AccountID: "acct", APIToken: "acct-tok", UserAPIToken: "user-tok"}

	if tok, err := cfg.parentTokenFor(tokenTypeAccount); err != nil || tok != "acct-tok" {
		t.Fatalf("account: got (%q, %v), want (acct-tok, nil)", tok, err)
	}
	if tok, err := cfg.parentTokenFor(""); err != nil || tok != "acct-tok" {
		t.Fatalf("default: got (%q, %v), want (acct-tok, nil)", tok, err)
	}
	if tok, err := cfg.parentTokenFor(tokenTypeUser); err != nil || tok != "user-tok" {
		t.Fatalf("user: got (%q, %v), want (user-tok, nil)", tok, err)
	}

	// Missing the matching credential must fail clearly.
	accountOnly := &cloudflareConfig{AccountID: "acct", APIToken: "acct-tok"}
	if _, err := accountOnly.parentTokenFor(tokenTypeUser); err == nil {
		t.Fatal("expected error requesting user token when only account creds configured")
	}
	userOnly := &cloudflareConfig{UserAPIToken: "user-tok"}
	if _, err := userOnly.parentTokenFor(tokenTypeAccount); err == nil {
		t.Fatal("expected error requesting account token when only user creds configured")
	}
}

func TestConfigWriteValidation(t *testing.T) {
	cases := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
	}{
		{"account only", map[string]interface{}{"cloudflare_account_id": "a", "cloudflare_api_token": "t"}, false},
		{"user only", map[string]interface{}{"cloudflare_user_api_token": "u"}, false},
		{"both", map[string]interface{}{"cloudflare_account_id": "a", "cloudflare_api_token": "t", "cloudflare_user_api_token": "u"}, false},
		{"account_id without token", map[string]interface{}{"cloudflare_account_id": "a"}, true},
		{"token without account_id", map[string]interface{}{"cloudflare_api_token": "t"}, true},
		{"nothing", map[string]interface{}{}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			storage := &logical.InmemStorage{}
			conf := logical.TestBackendConfig()
			conf.StorageView = storage
			b, err := Factory(ctx, conf)
			if err != nil {
				t.Fatalf("factory: %v", err)
			}

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Storage:   storage,
				Data:      c.data,
			})
			if err != nil {
				t.Fatalf("unexpected hard error: %v", err)
			}
			gotErr := resp != nil && resp.IsError()
			if gotErr != c.wantErr {
				t.Fatalf("wantErr=%v gotErr=%v (resp=%v)", c.wantErr, gotErr, resp)
			}
		})
	}
}

func TestConfigReadMasksBothTokens(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b, _ := Factory(ctx, conf)

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"cloudflare_account_id":     "acct",
			"cloudflare_api_token":      "secret-account-token",
			"cloudflare_user_api_token": "secret-user-token",
		},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, field := range []string{"cloudflare_api_token", "cloudflare_user_api_token"} {
		v, _ := resp.Data[field].(string)
		if strings.Contains(v, "secret-") {
			t.Fatalf("%s leaked unmasked: %q", field, v)
		}
		if !strings.HasPrefix(v, "x") {
			t.Fatalf("%s not masked: %q", field, v)
		}
	}
}
