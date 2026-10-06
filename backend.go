package cloudflaresecrets

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// PluginVersion is the running plugin version reported to Vault (shown by
// `vault plugin list` and used for pinning). It is set by the main package from
// build-time metadata; empty means unversioned.
var PluginVersion string

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
	// lock serializes read-modify-write mutations of the config and role
	// entries. Vault core does not serialize concurrent logical requests to the
	// same storage key across a Get+Put, so without this two concurrent writes
	// could lose an update (e.g. a rotated parent token clobbered back).
	lock sync.RWMutex
	// apiBaseURL, when non-empty, overrides the Cloudflare API base URL for
	// every client this backend builds. It is not settable through any
	// configured path: unit tests assign it directly, and the compiled plugin
	// honors the CLOUDFLARE_API_BASE_URL environment variable (set per plugin
	// at catalog registration, or on the Vault server process) so integration
	// suites can point it at a mock. The environment is operator-controlled -
	// the same trust level as the plugin binary itself.
	apiBaseURL string
}

// newClient builds a Cloudflare client for a parent token, applying the
// backend's API base override when set (tests only).
func (b *cloudflareBackend) newClient(token string) *cloudflareClient {
	c := newCloudflareClient(token)
	if b.apiBaseURL != "" {
		c.baseURL = b.apiBaseURL
	}
	return c
}

func newBackend() *cloudflareBackend {
	b := &cloudflareBackend{}
	if v := os.Getenv("CLOUDFLARE_API_BASE_URL"); v != "" {
		b.apiBaseURL = v
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathRole(b),
			[]*framework.Path{
				pathConfig(b),
				pathConfigRotateRoot(b),
				pathCreds(b),
			},
		),
		Secrets: []*framework.Secret{
			secretToken(b),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
		// Recovers interrupted root rotations (see walRotateRoot / walRollback).
		WALRollback:       b.walRollback,
		WALRollbackMinAge: 5 * time.Minute,
	}
	if PluginVersion != "" {
		b.Backend.RunningVersion = PluginVersion
	}

	return b
}

const backendHelp = `
The Cloudflare secrets engine generates dynamic, short-lived Cloudflare API
tokens. Configure it with a parent account ID and API token, then read from the
generate endpoint to mint scoped tokens. Each generated token is leased by Vault
and revoked (deleted from Cloudflare) when its lease expires.
`
