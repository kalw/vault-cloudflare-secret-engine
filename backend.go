package cloudflaresecrets

import (
	"context"
	"strings"
	"sync"

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

	lock   sync.RWMutex
	client *cloudflareClient
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
		Invalidate: b.invalidate,
	}

	return b
}

// reset drops the cached client so the next request rebuilds it from the
// current configuration.
func (b *cloudflareBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears the cached client whenever the config changes on another
// node in an HA cluster.
func (b *cloudflareBackend) invalidate(ctx context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

// getClient returns a cached Cloudflare client, building one from stored
// configuration on first use.
func (b *cloudflareBackend) getClient(ctx context.Context, s logical.Storage) (*cloudflareClient, error) {
	b.lock.RLock()
	if b.client != nil {
		client := b.client
		b.lock.RUnlock()
		return client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()

	// Re-check after acquiring the write lock.
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	b.client = newCloudflareClient(config.AccountID, config.APIToken)
	return b.client, nil
}

const backendHelp = `
The Cloudflare secrets engine generates dynamic, short-lived Cloudflare API
tokens. Configure it with a parent account ID and API token, then read from the
generate endpoint to mint scoped tokens. Each generated token is leased by Vault
and revoked (deleted from Cloudflare) when its lease expires.
`
