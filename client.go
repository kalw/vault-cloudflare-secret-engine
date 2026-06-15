package cloudflaresecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// cloudflareAPIBase is the root of the Cloudflare v4 REST API.
const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// Token contexts. Cloudflare mints either account-owned tokens (tied to a
// service, created under /accounts/{id}/tokens) or user-owned tokens (tied to
// an individual, created under /user/tokens). Permission groups and some
// operations are only available in one context or the other.
const (
	tokenTypeAccount = "account"
	tokenTypeUser    = "user"
)

// tokenScope identifies which Cloudflare context a token operation targets.
type tokenScope struct {
	Type      string // tokenTypeAccount or tokenTypeUser
	AccountID string // required for account-owned tokens
}

// basePath returns the API path prefix for this scope.
func (s tokenScope) basePath() (string, error) {
	switch s.Type {
	case tokenTypeUser:
		return "/user", nil
	case tokenTypeAccount, "":
		if s.AccountID == "" {
			return "", errors.New("account_id is required for account-owned tokens")
		}
		return "/accounts/" + s.AccountID, nil
	default:
		return "", fmt.Errorf("invalid token_type %q (must be %q or %q)", s.Type, tokenTypeAccount, tokenTypeUser)
	}
}

// cloudflareClient wraps the Cloudflare API token endpoints. It authenticates
// with a parent API token allowed to mint and delete other tokens.
type cloudflareClient struct {
	apiToken   string
	httpClient *http.Client
}

func newCloudflareClient(apiToken string) *cloudflareClient {
	return &cloudflareClient{
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// cfAPIError mirrors a single entry of the Cloudflare "errors" array.
type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfResponse is the standard Cloudflare API envelope.
type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// permissionGroup is a named bundle of permissions. In a policy only the ID is
// required; Name is accepted on input so operators can reference groups by
// human-readable name and let the plugin resolve them.
type permissionGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// policy is a single access policy attached to a token. Resources is passed
// through verbatim so the full Cloudflare resource model (account, zone,
// all-zones, user, r2, ...) is supported.
type policy struct {
	Effect           string            `json:"effect"`
	Resources        json.RawMessage   `json:"resources"`
	PermissionGroups []permissionGroup `json:"permission_groups"`
}

// createTokenRequest is the body for POST .../tokens.
type createTokenRequest struct {
	Name      string   `json:"name"`
	Policies  []policy `json:"policies"`
	ExpiresOn string   `json:"expires_on,omitempty"`
}

// tokenResult is the relevant subset of the create-token response.
type tokenResult struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// do performs an authenticated request and unwraps the response envelope.
func (c *cloudflareClient) do(ctx context.Context, method, path string, body, out interface{}) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPIBase+path, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var cfResp cfResponse
	if err := json.Unmarshal(data, &cfResp); err != nil {
		return fmt.Errorf("cloudflare: failed to parse response (status %d): %s", resp.StatusCode, string(data))
	}

	if !cfResp.Success {
		if len(cfResp.Errors) > 0 {
			return fmt.Errorf("cloudflare API error (status %d): code %d: %s",
				resp.StatusCode, cfResp.Errors[0].Code, cfResp.Errors[0].Message)
		}
		return fmt.Errorf("cloudflare API request failed with status %d", resp.StatusCode)
	}

	if out != nil && len(cfResp.Result) > 0 {
		if err := json.Unmarshal(cfResp.Result, out); err != nil {
			return err
		}
	}
	return nil
}

// listPermissionGroups returns the permission groups available in a scope.
func (c *cloudflareClient) listPermissionGroups(ctx context.Context, scope tokenScope) ([]permissionGroup, error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	var pgs []permissionGroup
	if err := c.do(ctx, http.MethodGet, base+"/tokens/permission_groups", nil, &pgs); err != nil {
		return nil, err
	}
	return pgs, nil
}

// createToken mints a new token in the given scope.
func (c *cloudflareClient) createToken(ctx context.Context, scope tokenScope, req *createTokenRequest) (*tokenResult, error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	var res tokenResult
	if err := c.do(ctx, http.MethodPost, base+"/tokens", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// deleteToken revokes a previously created token by ID in the given scope.
func (c *cloudflareClient) deleteToken(ctx context.Context, scope tokenScope, tokenID string) error {
	base, err := scope.basePath()
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, base+"/tokens/"+tokenID, nil, nil)
}
