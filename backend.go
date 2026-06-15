package cloudflaresecrets

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a configured Cloudflare secrets backend. It is the entry
// point referenced by the plugin's main package.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// cloudflareBackend implements logical.Backend for minting dynamic Cloudflare
// API tokens.
type cloudflareBackend struct {
	*framework.Backend
}

func newBackend() *cloudflareBackend {
	b := &cloudflareBackend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathRole(b),
			[]*framework.Path{
				pathConfig(b),
				pathCreds(b),
			},
		),
		Secrets: []*framework.Secret{
			secretToken(b),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
	}

	return b
}

// clientForTokenType loads the config and builds a Cloudflare client using the
// parent credential for the requested token context (account or user). It fails
// with a clear error when that context's credentials are not configured.
func (b *cloudflareBackend) clientForTokenType(ctx context.Context, s logical.Storage, tokenType string) (*cloudflareClient, error) {
	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	token, err := config.parentTokenFor(tokenType)
	if err != nil {
		return nil, err
	}
	return newCloudflareClient(token), nil
}

const backendHelp = `
The Cloudflare secrets engine generates dynamic, short-lived Cloudflare API
tokens. Configure it with a parent account ID and API token, then read from the
generate endpoint to mint scoped tokens. Each generated token is leased by Vault
and revoked (deleted from Cloudflare) when its lease expires.
`
