package cloudflaresecrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	// Select the parent credential for this role's token context; fail clearly
	// if that context is not configured.
	parentToken, err := config.parentTokenFor(scope.Type)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	client := b.newClient(parentToken)

	// Parse the role's stored policies and resolve permission group names → IDs.
	// The live permission group catalog is only fetched when a policy actually
	// references a group by name; ID-only policies skip the extra round-trip.
	policies, err := parsePolicies(string(role.Policies))
	if err != nil {
		return nil, fmt.Errorf("role %q has invalid stored policies: %w", roleName, err)
	}
	var groups []permissionGroup
	if policiesNeedNameResolution(policies) {
		groups, err = client.listPermissionGroups(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("error listing cloudflare permission groups: %w", err)
		}
	}
	if err := resolvePermissionGroups(policies, groups); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Cloudflare-side expiry backstop in case Vault never revokes. A buffer is
	// added on top of max_ttl so the Cloudflare token always outlives the Vault
	// lease's latest possible end (the lease is committed slightly after this
	// call, and clocks may skew); otherwise a lease renewed to its cap could
	// briefly wrap an already-expired token.
	backstop := maxTTL
	if backstop <= 0 {
		backstop = defaultMax
	}
	backstop += expiryBackstopBuffer

	// A random suffix keeps names unique for same-second mints; the timestamp
	// stays for operator forensics in the Cloudflare dashboard.
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return nil, fmt.Errorf("generating token name suffix: %w", err)
	}

	tokenReq := &createTokenRequest{
		Name:      fmt.Sprintf("vault-%s-%d-%s", roleName, time.Now().Unix(), hex.EncodeToString(suffix)),
		Policies:  policies,
		ExpiresOn: time.Now().UTC().Add(backstop).Format(time.RFC3339),
	}
	if len(role.RequestIPIn) > 0 || len(role.RequestIPNotIn) > 0 {
		tokenReq.Condition = &tokenCondition{RequestIP: &requestIP{
			In:    role.RequestIPIn,
			NotIn: role.RequestIPNotIn,
		}}
	}

	token, err := client.createToken(ctx, scope, tokenReq)
	if err != nil {
		return nil, fmt.Errorf("error creating cloudflare token: %w", err)
	}
	if token.ID == "" {
		return nil, fmt.Errorf("cloudflare returned a token with no ID; refusing to issue an unrevocable credential")
	}
	b.Logger().Info("minted cloudflare token", "role", roleName, "token_id", token.ID, "token_type", scope.Type)

	resp := b.Secret(cloudflareTokenType).Response(
		map[string]interface{}{
			"token":      token.Value,
			"token_id":   token.ID,
			"token_name": token.Name,
			"role":       roleName,
		},
		map[string]interface{}{
			// Internal data used at revoke and renew time.
			"token_id":   token.ID,
			"token_type": scope.Type,
			"account_id": scope.AccountID,
			// Effective lease bounds, persisted so renewal stays consistent
			// with the Cloudflare-side expires_on regardless of later config
			// or role changes.
			"ttl_seconds":     ttl.Seconds(),
			"max_ttl_seconds": maxTTL.Seconds(),
		},
	)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL

	// Optionally surface a derived R2 S3 keypair. The Access Key ID is the
	// token ID and the Secret Access Key is the hex SHA-256 of the token value;
	// both are invalidated when the lease is revoked (the token is deleted).
	if role.R2S3Credentials {
		resp.Data["r2_access_key_id"] = token.ID
		resp.Data["r2_secret_access_key"] = r2SecretAccessKey(token.Value)
		r2AccountID := scope.AccountID
		if r2AccountID == "" {
			r2AccountID = config.AccountID
		}
		if r2AccountID != "" {
			resp.Data["r2_endpoint"] = r2Endpoint(r2AccountID)
		}
	}

	return resp, nil
}

// policiesNeedNameResolution reports whether any policy references a permission
// group by name (i.e. without an ID), which requires fetching the live catalog.
func policiesNeedNameResolution(policies []policy) bool {
	for i := range policies {
		for _, pg := range policies[i].PermissionGroups {
			if pg.ID == "" {
				return true
			}
		}
	}
	return false
}

// resolvePermissionGroups rewrites each policy's permission groups so they carry
// a concrete Cloudflare ID, resolving any name-only references against the live
// permission group list. The Name field is cleared so the request sends IDs.
//
// Cloudflare's catalog can contain multiple groups that share a display name
// (across scopes/products). A name that maps to more than one distinct ID is
// rejected as ambiguous rather than silently resolved to whichever entry
// happened to be last, which could grant a broader group than intended.
func resolvePermissionGroups(policies []policy, all []permissionGroup) error {
	byName := make(map[string]map[string]struct{}, len(all))
	for _, pg := range all {
		key := strings.ToLower(pg.Name)
		if byName[key] == nil {
			byName[key] = make(map[string]struct{})
		}
		byName[key][pg.ID] = struct{}{}
	}

	for i := range policies {
		for j := range policies[i].PermissionGroups {
			pg := &policies[i].PermissionGroups[j]
			if pg.ID == "" {
				ids := byName[strings.ToLower(pg.Name)]
				switch len(ids) {
				case 0:
					return fmt.Errorf("unknown cloudflare permission group name %q", pg.Name)
				case 1:
					for id := range ids {
						pg.ID = id
					}
				default:
					return fmt.Errorf("cloudflare permission group name %q is ambiguous: %d groups share it; reference it by id instead", pg.Name, len(ids))
				}
			}
			pg.Name = ""
		}
	}
	return nil
}
