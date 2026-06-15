package cloudflaresecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// errBackendNotConfigured is returned when an operation needs configuration
// that has not been written yet.
var errBackendNotConfigured = errors.New("cloudflare backend not configured; write to the config endpoint first")

// Default lease bounds for generated tokens.
const (
	defaultTTL = time.Hour
	defaultMax = 24 * time.Hour
)

// cloudflareConfig is the persisted backend configuration.
type cloudflareConfig struct {
	AccountID string        `json:"cloudflare_account_id"`
	APIToken  string        `json:"cloudflare_api_token"`
	TTL       time.Duration `json:"ttl"`
	MaxTTL    time.Duration `json:"max_ttl"`
}

func pathConfig(b *cloudflareBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"cloudflare_account_id": {
				Type:        framework.TypeString,
				Description: "Cloudflare account ID that owns the generated tokens.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Cloudflare Account ID",
				},
			},
			"cloudflare_api_token": {
				Type:        framework.TypeString,
				Description: "Parent Cloudflare API token used to mint and revoke tokens. Requires the 'API Tokens Write' permission.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Cloudflare API Token",
					Sensitive: true,
				},
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL for generated tokens. Defaults to 1h.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL for generated tokens. Also used as the Cloudflare-side expiry backstop. Defaults to 24h.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    "Configure the Cloudflare secrets engine.",
		HelpDescription: "Configure the parent credentials and lease defaults used to generate Cloudflare API tokens.",
	}
}

func (b *cloudflareBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

func (b *cloudflareBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cloudflare_account_id": config.AccountID,
			"cloudflare_api_token":  maskToken(config.APIToken),
			"ttl":                   int64(config.TTL.Seconds()),
			"max_ttl":               int64(config.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *cloudflareBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation
	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = &cloudflareConfig{}
	}

	if v, ok := d.GetOk("cloudflare_account_id"); ok {
		config.AccountID = v.(string)
	} else if createOperation {
		return logical.ErrorResponse("missing cloudflare_account_id"), nil
	}

	if v, ok := d.GetOk("cloudflare_api_token"); ok {
		config.APIToken = v.(string)
	} else if createOperation {
		return logical.ErrorResponse("missing cloudflare_api_token"), nil
	}

	if v, ok := d.GetOk("ttl"); ok {
		config.TTL = time.Duration(v.(int)) * time.Second
	} else if createOperation {
		config.TTL = defaultTTL
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		config.MaxTTL = time.Duration(v.(int)) * time.Second
	} else if createOperation {
		config.MaxTTL = defaultMax
	}

	if config.MaxTTL > 0 && config.TTL > config.MaxTTL {
		return logical.ErrorResponse("ttl cannot exceed max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Drop the cached client so subsequent calls pick up the new credentials.
	b.reset()

	return nil, nil
}

func (b *cloudflareBackend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)
	if err == nil {
		b.reset()
	}
	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*cloudflareConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &cloudflareConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("error reading cloudflare configuration: %w", err)
	}

	// Backfill defaults for configs written before these fields existed.
	if config.TTL == 0 {
		config.TTL = defaultTTL
	}
	if config.MaxTTL == 0 {
		config.MaxTTL = defaultMax
	}
	return config, nil
}

// maskToken returns the token with all but the last four characters hidden.
func maskToken(token string) string {
	if len(token) <= 4 {
		return strings.Repeat("x", len(token))
	}
	return strings.Repeat("x", len(token)-4) + token[len(token)-4:]
}
