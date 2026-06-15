package cloudflaresecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// cloudflareRoleEntry defines how tokens are minted for a role. It captures the
// Cloudflare token context (account vs user) and the full policy set (ACL +
// resources) that every generated token receives.
type cloudflareRoleEntry struct {
	TokenType string          `json:"token_type"`
	AccountID string          `json:"account_id,omitempty"`
	Policies  json.RawMessage `json:"policies"`
	TTL       time.Duration   `json:"ttl"`
	MaxTTL    time.Duration   `json:"max_ttl"`
}

func (r *cloudflareRoleEntry) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"token_type": r.TokenType,
		"account_id": r.AccountID,
		"policies":   json.RawMessage(r.Policies),
		"ttl":        int64(r.TTL.Seconds()),
		"max_ttl":    int64(r.MaxTTL.Seconds()),
	}
}

func pathRole(b *cloudflareBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
				"token_type": {
					Type:        framework.TypeString,
					Description: `Cloudflare token context: "account" (service-tied, default) or "user" (tied to the individual that owns the parent token).`,
					Default:     tokenTypeAccount,
				},
				"account_id": {
					Type:        framework.TypeString,
					Description: "Account ID for account-owned tokens. Defaults to the backend config's cloudflare_account_id.",
				},
				"policies": {
					Type:        framework.TypeString,
					Description: `JSON array of Cloudflare token policies. Each policy has "effect" (default "allow"), "permission_groups" (each entry by {"id":...} or {"name":...}), and "resources" (the Cloudflare resource map).`,
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease TTL for tokens from this role. Falls back to the backend config ttl.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease TTL for tokens from this role. Falls back to the backend config max_ttl.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDelete},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    "Manage roles used to generate Cloudflare tokens.",
			HelpDescription: "A role defines the token context (account/user) and the policy set (ACL + resources) applied to every token it generates.",
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
			},
			HelpSynopsis:    "List the configured Cloudflare roles.",
			HelpDescription: "List the existing roles in the Cloudflare secrets backend by name.",
		},
	}
}

func (b *cloudflareBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, fmt.Errorf("error reading role: %w", err)
	}
	return entry != nil, nil
}

func (b *cloudflareBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *cloudflareBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &logical.Response{Data: entry.toResponseData()}, nil
}

func (b *cloudflareBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}
	createOperation := req.Operation == logical.CreateOperation
	if role == nil {
		role = &cloudflareRoleEntry{}
	}

	if v, ok := d.GetOk("token_type"); ok {
		role.TokenType = v.(string)
	} else if createOperation {
		role.TokenType = tokenTypeAccount
	}
	if role.TokenType != tokenTypeAccount && role.TokenType != tokenTypeUser {
		return logical.ErrorResponse("token_type must be %q or %q", tokenTypeAccount, tokenTypeUser), nil
	}

	if v, ok := d.GetOk("account_id"); ok {
		role.AccountID = v.(string)
	}

	if v, ok := d.GetOk("policies"); ok {
		policies, err := parsePolicies(v.(string))
		if err != nil {
			return logical.ErrorResponse("invalid policies: %s", err), nil
		}
		// Re-marshal the validated policies so storage holds canonical JSON.
		canonical, err := json.Marshal(policies)
		if err != nil {
			return nil, err
		}
		role.Policies = canonical
	} else if createOperation {
		return logical.ErrorResponse("missing policies"), nil
	}

	if v, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot exceed max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON("role/"+name.(string), role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *cloudflareBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string)); err != nil {
		return nil, fmt.Errorf("error deleting cloudflare role: %w", err)
	}
	return nil, nil
}

func (b *cloudflareBackend) getRole(ctx context.Context, s logical.Storage, name string) (*cloudflareRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}
	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var role cloudflareRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// parsePolicies validates the operator-supplied policies JSON and applies
// defaults (effect=allow). It does not resolve permission group names to IDs;
// that happens at generation time against the live permission group list.
func parsePolicies(raw string) ([]policy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("policies is empty")
	}

	var policies []policy
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&policies); err != nil {
		return nil, fmt.Errorf("must be a JSON array of policy objects: %w", err)
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("at least one policy is required")
	}

	for i := range policies {
		p := &policies[i]
		if p.Effect == "" {
			p.Effect = "allow"
		}
		if p.Effect != "allow" && p.Effect != "deny" {
			return nil, fmt.Errorf("policy %d: effect must be \"allow\" or \"deny\"", i)
		}
		if len(p.PermissionGroups) == 0 {
			return nil, fmt.Errorf("policy %d: at least one permission_group is required", i)
		}
		for j, pg := range p.PermissionGroups {
			if pg.ID == "" && pg.Name == "" {
				return nil, fmt.Errorf("policy %d: permission_group %d needs an \"id\" or \"name\"", i, j)
			}
		}
		if len(p.Resources) == 0 {
			return nil, fmt.Errorf("policy %d: resources is required", i)
		}
	}
	return policies, nil
}
