# vault-cloudflare-secret-engine

This plugin will allow you to create a secret backend that will use the cloudflare API to generate dynamic short lived cloudflare token.  Usage can be restricted using the highly customizable Vault ACL system.

### Setup

Most secrets engines must be configured in advance before they can perform their
functions. These steps are usually completed by an operator or configuration
management tool.

1. Register the plugin with the catalog

    ```text
    $ SHASUM=$(shasum -a 256 vault-cloudflare-secret-engine | cut -d " " -f1)
    $ vault write sys/plugins/catalog/vault-cloudflare-secret-engine sha_256="$SHASUM" command="vault-cloudflare-secret-engine" 
    Success! Data written to: sys/plugins/catalog/vault-cloudflare-secret-engine
    ```

1. Enable the cloudflare secrets engine:

    ```text
    $ vault secrets enable -path="cloudflare" -plugin-name="vault-cloudflare-secret-engine" plugin
    Success! Enabled the vault-cloudflare-secret-engine plugin at: cloudflare/
    ```

    By default, the secrets engine will mount at the name of the engine. To
    enable the secrets engine at a different path, use the `-path` argument.

1. Configure the backend with the parent credentials used to mint and revoke tokens.

    The config holds a credential per **token context** — provide account
    credentials, user credentials, or both. A role's `token_type` then selects
    which one is used, and generation fails if the matching context is not
    configured.

    ```text
    # account context (token_type=account)
    $ vault write cloudflare/config \
        cloudflare_account_id="<account-id>" \
        cloudflare_api_token="<account-parent-token>"

    # user context (token_type=user) — can be set instead of, or alongside, the above
    $ vault write cloudflare/config \
        cloudflare_user_api_token="<user-parent-token>"
    ```

    | Field | Context | Cloudflare permission the parent token needs |
    | --- | --- | --- |
    | `cloudflare_account_id` + `cloudflare_api_token` | account | Account · API Tokens · Edit |
    | `cloudflare_user_api_token` | user | User · API Tokens · Edit |

    At least one context must be configured (`cloudflare_account_id` and
    `cloudflare_api_token` must be set together). Tokens are stored seal-wrapped
    and never returned in plaintext. Optional `ttl` and `max_ttl` fields control
    the lease duration of generated tokens (defaults: `1h` / `24h`).

### Roles

Tokens are generated from **roles**. A role defines two things:

- **`token_type`** — the Cloudflare token context: `account` (default; service-tied,
  survives an employee leaving) or `user` (tied to the individual that owns the
  parent API token). Some permission groups and operations are only available in
  one context or the other. The matching credential must be configured (see
  Setup) — a `token_type=user` role fails unless `cloudflare_user_api_token` is
  set, and likewise for the account context.
- **`policies`** — a JSON array that maps 1:1 to Cloudflare's token policy model.
  Each policy has an `effect` (`allow`/`deny`, default `allow`), a list of
  `permission_groups`, and a `resources` map. This is where the token's ACL and
  scope live.

Permission groups may be referenced by `id` **or** by `name` — names are
resolved against Cloudflare's live permission-group list when a token is
generated.

```text
$ vault write cloudflare/role/dns-editor \
    token_type="account" \
    ttl="30m" \
    policies='[
      {
        "effect": "allow",
        "permission_groups": [
          {"name": "DNS Write"},
          {"name": "Zone Read"}
        ],
        "resources": {
          "com.cloudflare.api.account.zone.<zone-id>": "*"
        }
      }
    ]'
Success! Data written to: cloudflare/role/dns-editor
```

The `resources` map accepts the full Cloudflare resource model, for example:

| Intent                | `resources` value |
| --------------------- | ----------------- |
| A specific zone       | `{"com.cloudflare.api.account.zone.<zone-id>": "*"}` |
| The whole account     | `{"com.cloudflare.api.account.<account-id>": "*"}` |
| All zones in account  | `{"com.cloudflare.api.account.<account-id>": {"com.cloudflare.api.account.zone.*": "*"}}` |
| A user                | `{"com.cloudflare.api.user.<user-id>": "*"}` |

List and read roles with `vault list cloudflare/role` and
`vault read cloudflare/role/dns-editor`.

### Usage

After a role exists, read its credentials endpoint to mint a token:

```text
$ vault read cloudflare/creds/dns-editor
Key                Value
---                -----
lease_id           cloudflare/creds/dns-editor/9f3c...
lease_duration     30m
lease_renewable    true
role               dns-editor
token              v1.0-d118a65cdfe314202cf969e1fb2e8afc-...
token_id           ed17574386854bf78a67040be0a770b0
token_name         vault-dns-editor-1718450000
```

Each generated token is leased by Vault. When the lease expires or is revoked,
the plugin deletes the token from Cloudflare. A Cloudflare-side expiry equal to
the effective `max_ttl` is also set as a backstop in case Vault never revokes.

Because generation is gated on `cloudflare/creds/<role>`, the standard Vault ACL
system restricts which identities may use which roles.

## Local Development

### Build the code

```bash
docker build -t vault-plugin .
docker run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:1234' -p 1234:1234 vault-plugin
```

To build just the plugin binary for the host platform:

```bash
go build -o vault-cloudflare-secret-engine ./cmd/vault-cloudflare-secret-engine
```

### Configure the local vault

In a second terminal window...

```bash
export VAULT_ADDR='http://0.0.0.0:1234'
vault login myroot

# The Docker image builds the plugin internally, so the SHA-256 must be taken
# from the binary inside the container (Vault hashes that exact file). Hashing a
# separately built host binary will fail with "checksums did not match".
CID=$(docker ps -q --filter ancestor=vault-plugin | head -1)
SHASUM=$(docker exec "$CID" sha256sum /vault/plugins/vault-cloudflare-secret-engine | cut -d ' ' -f1)

vault write sys/plugins/catalog/vault-cloudflare-secret-engine sha_256="$SHASUM" command="vault-cloudflare-secret-engine"
vault secrets enable -path="cloudflare" -plugin-name="vault-cloudflare-secret-engine" plugin
vault write cloudflare/config cloudflare_account_id="<account-id>" cloudflare_api_token="<parent-api-token>"
```

> Tip: `-dev-plugin-dir=/vault/plugins` on the dev server auto-registers plugins
> and skips the manual `sha_256` registration entirely — handy for iterating.

### Tests

Unit tests run with no external dependencies:

```bash
go test ./...
```

There is also an acceptance test that mints and revokes a real token against
the live Cloudflare API. It is skipped unless `VAULT_ACC` is set:

The test has two subtests, one per token context:

```bash
export VAULT_ACC=1
export CLOUDFLARE_ACCOUNT_ID="<account-id>"

# account-context case (token_type=account)
export CLOUDFLARE_API_TOKEN="<parent-account-token>"   # needs "Account · API Tokens · Edit"
# Optional: override the role's policies (defaults to a low-privilege
# "Account Settings Read" policy scoped to the account).
# export CLOUDFLARE_TEST_POLICIES='[{"effect":"allow","permission_groups":[{"name":"DNS Read"}],"resources":{"com.cloudflare.api.account.zone.<zone-id>":"*"}}]'

# user-context case (token_type=user) — runs only when this is set
export CLOUDFLARE_USER_API_TOKEN="<parent-user-token>"  # needs "User · API Tokens · Edit"
# export CLOUDFLARE_USER_TEST_POLICIES='[...]'

go test -run TestAcceptance -v
```

The `user` subtest is skipped unless `CLOUDFLARE_USER_API_TOKEN` is set. Both
cases default to the same account-scoped policy, since account-scoped permission
groups are valid in user-owned tokens.
