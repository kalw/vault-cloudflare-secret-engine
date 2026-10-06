package cloudflaresecrets

import (
	"context"
	"errors"
	"fmt"
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

	// expiryBackstopBuffer is added to a token's max_ttl when setting its
	// Cloudflare-side expires_on, so the token always outlives the Vault lease's
	// latest possible end despite lease-commit delay and clock skew.
	expiryBackstopBuffer = 5 * time.Minute
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
	b.lock.Lock()
	defer b.lock.Unlock()

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
	if config.AccountID != "" {
		if err := validateAccountID(config.AccountID); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
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
	b.lock.Lock()
	defer b.lock.Unlock()

	return nil, req.Storage.Delete(ctx, configStoragePath)
}

func pathConfigRotateRoot(b *cloudflareBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Fields: map[string]*framework.FieldSchema{
			"token_type": {
				Type:        framework.TypeString,
				Description: `Which parent credential to rotate: "account" (default) or "user".`,
				Default:     tokenTypeAccount,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigRotateRoot},
		},
		HelpSynopsis: "Rotate a parent Cloudflare API token in place.",
		HelpDescription: `Rolls the configured parent token's value via the Cloudflare API and
stores the new value, so the bootstrap credential is owned and rotatable by
Vault. The token's ID and permissions are preserved; only the secret changes.
The plaintext value is never returned.`,
	}
}

// pathConfigRotateRoot rolls a configured parent token's value and persists it.
// It discovers the token's own ID via the verify endpoint, rolls the value, and
// writes the new value back to config. The old value is invalidated by
// Cloudflare, so the bootstrap credential becomes Vault-owned.
func (b *cloudflareBackend) pathConfigRotateRoot(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	tokenType := d.Get("token_type").(string)
	if tokenType != tokenTypeAccount && tokenType != tokenTypeUser {
		return logical.ErrorResponse("token_type must be %q or %q", tokenTypeAccount, tokenTypeUser), nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	token, err := config.parentTokenFor(tokenType)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	scope := tokenScope{Type: tokenType, AccountID: config.AccountID}
	client := b.newClient(token)

	tokenID, err := client.verifyToken(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("verifying parent token before rotation: %w", err)
	}
	newValue, err := client.rollToken(ctx, scope, tokenID)
	if err != nil {
		return nil, fmt.Errorf("rolling parent token: %w", err)
	}
	if newValue == "" {
		return nil, fmt.Errorf("cloudflare returned an empty value when rolling the parent token")
	}

	switch tokenType {
	case tokenTypeUser:
		config.UserAPIToken = newValue
	default:
		config.APIToken = newValue
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err == nil {
		err = req.Storage.Put(ctx, entry)
	}
	if err != nil {
		// The Cloudflare-side roll already happened: the old value is dead and
		// the new one exists only in this process. Without a successful write,
		// the stored parent credential is now invalid. Be explicit about
		// recovery instead of failing opaquely.
		b.Logger().Error("parent token was rolled at Cloudflare but the new value could not be persisted",
			"token_type", tokenType, "token_id", tokenID, "error", err)
		return nil, fmt.Errorf(
			"parent token (id %s) was rolled at Cloudflare but persisting the new value failed: %w. "+
				"The stored %s credential is now invalid: retry this rotation immediately (it rolls again and persists), "+
				"or mint a fresh parent token in the Cloudflare dashboard and write it to the config endpoint",
			tokenID, err, tokenType)
	}
	b.Logger().Info("rotated parent cloudflare token", "token_type", tokenType, "token_id", tokenID)

	return &logical.Response{
		Data: map[string]interface{}{
			"token_type": tokenType,
			"token_id":   tokenID,
			"rotated":    true,
		},
	}, nil
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

// redactedToken is the fixed placeholder returned for a configured token. It
// reveals neither the token's length nor any of its characters.
const redactedToken = "***redacted***"

// maskToken reports whether a token is configured without disclosing any of its
// bytes or its length: empty stays empty, anything else becomes a fixed marker.
func maskToken(token string) string {
	if token == "" {
		return ""
	}
	return redactedToken
}
