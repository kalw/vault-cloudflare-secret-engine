package cloudflaresecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreds(b *cloudflareBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to generate a token from.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredsRead},
		},
		HelpSynopsis:    "Generate a dynamic Cloudflare API token from a role.",
		HelpDescription: "Mints a short-lived Cloudflare API token using the named role's token context and policies. The token is leased and revoked (deleted from Cloudflare) on expiry.",
	}
}

func (b *cloudflareBackend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	// Resolve the token scope (account vs user) for this role.
	scope := tokenScope{Type: role.TokenType}
	if scope.Type == "" {
		scope.Type = tokenTypeAccount
	}
	if scope.Type == tokenTypeAccount {
		scope.AccountID = role.AccountID
		if scope.AccountID == "" {
			scope.AccountID = config.AccountID
		}
		if scope.AccountID == "" {
			return logical.ErrorResponse("role %q is an account token but no account_id is set on the role or config", roleName), nil
		}
	}

	// Resolve lease bounds: role overrides config; ttl capped by max_ttl.
	ttl := config.TTL
	if role.TTL > 0 {
		ttl = role.TTL
	}
	maxTTL := config.MaxTTL
	if role.MaxTTL > 0 {
		maxTTL = role.MaxTTL
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Parse the role's stored policies and resolve permission group names → IDs.
	policies, err := parsePolicies(string(role.Policies))
	if err != nil {
		return nil, fmt.Errorf("role %q has invalid stored policies: %w", roleName, err)
	}
	groups, err := client.listPermissionGroups(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("error listing cloudflare permission groups: %w", err)
	}
	if err := resolvePermissionGroups(policies, groups); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Cloudflare-side expiry backstop in case Vault never revokes.
	backstop := maxTTL
	if backstop <= 0 {
		backstop = defaultMax
	}

	tokenReq := &createTokenRequest{
		Name:      fmt.Sprintf("vault-%s-%d", roleName, time.Now().Unix()),
		Policies:  policies,
		ExpiresOn: time.Now().UTC().Add(backstop).Format(time.RFC3339),
	}

	token, err := client.createToken(ctx, scope, tokenReq)
	if err != nil {
		return nil, fmt.Errorf("error creating cloudflare token: %w", err)
	}

	resp := b.Secret(cloudflareTokenType).Response(
		map[string]interface{}{
			"token":      token.Value,
			"token_id":   token.ID,
			"token_name": token.Name,
			"role":       roleName,
		},
		map[string]interface{}{
			// Internal data used at revoke time.
			"token_id":   token.ID,
			"token_type": scope.Type,
			"account_id": scope.AccountID,
		},
	)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL

	return resp, nil
}

// resolvePermissionGroups rewrites each policy's permission groups so they carry
// a concrete Cloudflare ID, resolving any name-only references against the live
// permission group list. The Name field is cleared so the request sends IDs.
func resolvePermissionGroups(policies []policy, all []permissionGroup) error {
	byName := make(map[string]string, len(all))
	for _, pg := range all {
		byName[strings.ToLower(pg.Name)] = pg.ID
	}

	for i := range policies {
		for j := range policies[i].PermissionGroups {
			pg := &policies[i].PermissionGroups[j]
			if pg.ID == "" {
				id, ok := byName[strings.ToLower(pg.Name)]
				if !ok {
					return fmt.Errorf("unknown cloudflare permission group name %q", pg.Name)
				}
				pg.ID = id
			}
			pg.Name = ""
		}
	}
	return nil
}
