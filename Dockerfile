# Build the plugin binary, then run it inside an official Vault dev container.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/vault-cloudflare-secret-engine ./cmd/vault-cloudflare-secret-engine

FROM hashicorp/vault:latest
COPY --from=build /out/vault-cloudflare-secret-engine /vault/plugins/vault-cloudflare-secret-engine
ENV VAULT_LOCAL_CONFIG='{"plugin_directory":"/vault/plugins"}'
