package cloudflaresecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// cloudflareTokenType is the secret type registered for generated tokens.
const cloudflareTokenType = "cloudflare_token"

func secretToken(b *cloudflareBackend) *framework.Secret {
	return &framework.Secret{
		Type: cloudflareTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The Cloudflare API token value.",
			},
			"token_id": {
				Type:        framework.TypeString,
				Description: "The Cloudflare token identifier.",
			},
		},
		Revoke: b.secretTokenRevoke,
		Renew:  b.secretTokenRenew,
	}
}

// secretTokenRevoke deletes the Cloudflare token when its lease expires or is
// explicitly revoked.
func (b *cloudflareBackend) secretTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID, ok := req.Secret.InternalData["token_id"].(string)
	if !ok || tokenID == "" {
		return nil, errors.New("secret is missing token_id internal data")
	}

	scope := tokenScope{}
	if v, ok := req.Secret.InternalData["token_type"].(string); ok {
		scope.Type = v
	}
	if v, ok := req.Secret.InternalData["account_id"].(string); ok {
		scope.AccountID = v
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := client.deleteToken(ctx, scope, tokenID); err != nil {
		return nil, fmt.Errorf("error revoking cloudflare token %s: %w", tokenID, err)
	}
	return nil, nil
}

// secretTokenRenew extends the Vault lease. The Cloudflare-side expiry was set
// to max_ttl at creation, so renewals within that window need no API call.
func (b *cloudflareBackend) secretTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{Secret: req.Secret}
	if config != nil {
		resp.Secret.TTL = config.TTL
		resp.Secret.MaxTTL = config.MaxTTL
	}
	return resp, nil
}
