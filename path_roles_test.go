package cloudflaresecrets

import (
	"encoding/json"
	"testing"
)

var samplePermissionGroups = []permissionGroup{
	{ID: "pg-dns-read", Name: "DNS Read"},
	{ID: "pg-zone-read", Name: "Zone Read"},
	{ID: "pg-dns-write", Name: "DNS Write"},
}

func TestParsePolicies_Valid(t *testing.T) {
	raw := `[
		{
			"permission_groups": [{"name": "DNS Read"}, {"id": "pg-zone-read"}],
			"resources": {"com.cloudflare.api.account.zone.abc": "*"}
		}
	]`
	policies, err := parsePolicies(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Effect != "allow" {
		t.Fatalf("expected default effect 'allow', got %q", policies[0].Effect)
	}
}

func TestParsePolicies_Invalid(t *testing.T) {
	cases := map[string]string{
		"empty":            ``,
		"not an array":     `{"permission_groups": []}`,
		"no permissions":   `[{"resources": {"x": "*"}}]`,
		"no resources":     `[{"permission_groups": [{"id": "a"}]}]`,
		"pg without id/nm": `[{"permission_groups": [{}], "resources": {"x": "*"}}]`,
		"bad effect":       `[{"effect": "maybe", "permission_groups": [{"id": "a"}], "resources": {"x": "*"}}]`,
	}
	for name, raw := range cases {
		if _, err := parsePolicies(raw); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParsePolicies_NestedResources(t *testing.T) {
	// All-zones-in-account nested resource form must be accepted verbatim.
	raw := `[
		{
			"permission_groups": [{"id": "pg-dns-read"}],
			"resources": {
				"com.cloudflare.api.account.acct123": {"com.cloudflare.api.account.zone.*": "*"}
			}
		}
	]`
	policies, err := parsePolicies(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies[0].Resources) == 0 {
		t.Fatal("resources were dropped")
	}
}

func TestResolvePermissionGroups_ByName(t *testing.T) {
	policies := []policy{
		{
			PermissionGroups: []permissionGroup{{Name: "DNS Read"}, {ID: "pg-dns-write"}},
			Resources:        json.RawMessage(`{"x":"*"}`),
		},
	}
	if err := resolvePermissionGroups(policies, samplePermissionGroups); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pgs := policies[0].PermissionGroups
	if pgs[0].ID != "pg-dns-read" {
		t.Fatalf("expected name resolved to pg-dns-read, got %q", pgs[0].ID)
	}
	if pgs[0].Name != "" {
		t.Fatalf("expected Name cleared after resolution, got %q", pgs[0].Name)
	}
	if pgs[1].ID != "pg-dns-write" {
		t.Fatalf("expected passthrough id pg-dns-write, got %q", pgs[1].ID)
	}
}

func TestPoliciesNeedNameResolution(t *testing.T) {
	idOnly := []policy{{PermissionGroups: []permissionGroup{{ID: "a"}, {ID: "b"}}}}
	if policiesNeedNameResolution(idOnly) {
		t.Fatal("ID-only policies should not need name resolution (would trigger a needless API call)")
	}
	withName := []policy{{PermissionGroups: []permissionGroup{{ID: "a"}, {Name: "DNS Read"}}}}
	if !policiesNeedNameResolution(withName) {
		t.Fatal("a name-only permission group must require resolution")
	}
}

func TestResolvePermissionGroups_ClearsNameWithoutCatalog(t *testing.T) {
	// When no name resolution is needed, resolve is still called with a nil
	// catalog and must pass through IDs while clearing any stray names.
	policies := []policy{{PermissionGroups: []permissionGroup{{ID: "a", Name: "DNS Read"}}}}
	if err := resolvePermissionGroups(policies, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pg := policies[0].PermissionGroups[0]
	if pg.ID != "a" || pg.Name != "" {
		t.Fatalf("expected {id:a name:\"\"}, got {id:%s name:%q}", pg.ID, pg.Name)
	}
}

func TestResolvePermissionGroups_UnknownName(t *testing.T) {
	policies := []policy{
		{
			PermissionGroups: []permissionGroup{{Name: "Nonexistent Group"}},
			Resources:        json.RawMessage(`{"x":"*"}`),
		},
	}
	if err := resolvePermissionGroups(policies, samplePermissionGroups); err == nil {
		t.Fatal("expected error for unknown permission group name")
	}
}

func TestTokenScopeBasePath(t *testing.T) {
	cases := []struct {
		scope   tokenScope
		want    string
		wantErr bool
	}{
		{tokenScope{Type: tokenTypeUser}, "/user", false},
		{tokenScope{Type: tokenTypeAccount, AccountID: "abc"}, "/accounts/abc", false},
		{tokenScope{Type: "", AccountID: "abc"}, "/accounts/abc", false},
		{tokenScope{Type: tokenTypeAccount}, "", true},
		{tokenScope{Type: "bogus"}, "", true},
	}
	for _, c := range cases {
		got, err := c.scope.basePath()
		if c.wantErr {
			if err == nil {
				t.Errorf("%+v: expected error", c.scope)
			}
			continue
		}
		if err != nil {
			t.Errorf("%+v: unexpected error: %v", c.scope, err)
		}
		if got != c.want {
			t.Errorf("%+v: expected %q, got %q", c.scope, c.want, got)
		}
	}
}

func TestMaskToken(t *testing.T) {
	if got := maskToken("abcdef1234"); got != "xxxxxx1234" {
		t.Fatalf("expected xxxxxx1234, got %s", got)
	}
	if got := maskToken("abc"); got != "xxx" {
		t.Fatalf("expected xxx, got %s", got)
	}
}
