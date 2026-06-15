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

// cloudflareConfig is the persisted backend configuration. It can hold
// credentials for the account context, the user context, or both; a role's
// token_type selects which credential is used.
type cloudflareConfig struct {
	AccountID    string        `json:"cloudflare_account_id"`
	APIToken     string        `json:"cloudflare_api_token"`
	UserAPIToken string        `json:"cloudflare_user_api_token"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
}

// parentTokenFor returns the configured parent API token for a token context,
// or an error explaining which credential is missing.
func (c *cloudflareConfig) parentTokenFor(tokenType string) (string, error) {
	switch tokenType {
	case tokenTypeUser:
		if c.UserAPIToken == "" {
			return "", fmt.Errorf("user credentials are not configured: set cloudflare_user_api_token on the config to use token_type=user roles")
		}
		return c.UserAPIToken, nil
	case tokenTypeAccount, "":
		if c.APIToken == "" {
			return "", fmt.Errorf("account credentials are not configured: set cloudflare_account_id and cloudflare_api_token on the config to use token_type=account roles")
		}
		return c.APIToken, nil
	default:
		return "", fmt.Errorf("invalid token_type %q", tokenType)
	}
}

func pathConfig(b *cloudflareBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"cloudflare_account_id": {
				Type:        framework.TypeString,
				Description: "Cloudflare account ID that owns account-context tokens. Required together with cloudflare_api_token.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Cloudflare Account ID",
				},
			},
			"cloudflare_api_token": {
				Type:        framework.TypeString,
				Description: "Parent token for the account context (token_type=account). Needs 'Account · API Tokens · Edit'.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Cloudflare API Token",
					Sensitive: true,
				},
			},
			"cloudflare_user_api_token": {
				Type:        framework.TypeString,
				Description: "Parent token for the user context (token_type=user). Needs 'User · API Tokens · Edit'.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Cloudflare User API Token",
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
			"cloudflare_account_id":     config.AccountID,
			"cloudflare_api_token":      maskToken(config.APIToken),
			"cloudflare_user_api_token": maskToken(config.UserAPIToken),
			"ttl":                       int64(config.TTL.Seconds()),
			"max_ttl":                   int64(config.MaxTTL.Seconds()),
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
	}
	if v, ok := d.GetOk("cloudflare_api_token"); ok {
		config.APIToken = v.(string)
	}
	if v, ok := d.GetOk("cloudflare_user_api_token"); ok {
		config.UserAPIToken = v.(string)
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

	// The account context needs both the account ID and its token.
	if (config.AccountID == "") != (config.APIToken == "") {
		return logical.ErrorResponse("account credentials require both cloudflare_account_id and cloudflare_api_token"), nil
	}
	// At least one usable context (account and/or user) must be configured.
	hasAccount := config.AccountID != "" && config.APIToken != ""
	hasUser := config.UserAPIToken != ""
	if !hasAccount && !hasUser {
		return logical.ErrorResponse("configure account credentials (cloudflare_account_id + cloudflare_api_token) and/or a user credential (cloudflare_user_api_token)"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *cloudflareBackend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, configStoragePath)
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
