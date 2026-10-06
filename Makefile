NAME?=vault-cloudflare-secret-engine
# Vault version used by `make test-vault`. CI runs a matrix over the supported
# releases; `latest` resolves to the newest GA release via HashiCorp checkpoint.
VAULT_VERSION?=latest
ifeq ($(VAULT_VERSION),latest)
override VAULT_VERSION:=$(shell curl -fsSL https://checkpoint-api.hashicorp.com/v1/check/vault | sed -E 's/.*"current_version":"([^"]+)".*/\1/')
endif
VAULT_OS:=$(shell uname -s | tr A-Z a-z)
VAULT_ARCH:=$(patsubst x86_64,amd64,$(patsubst aarch64,arm64,$(shell uname -m)))

.DEFAULT_GOAL := all
all: build test

build:
	CGO_ENABLED=0 go build ./...

test:
	go test ./... -count=1

# Run the compiled plugin inside a real Vault $(VAULT_VERSION) dev server,
# against a fake Cloudflare API.
test-vault: .tools/vault-$(VAULT_VERSION)
	VAULT_BIN=$(shell pwd)/.tools/vault-$(VAULT_VERSION) go test -count=1 -v ./integration/ $(TESTARGS)

.tools:
	@mkdir -p .tools

.tools/vault-$(VAULT_VERSION): | .tools
	curl -fsSL -o .tools/vault-$(VAULT_VERSION).zip https://releases.hashicorp.com/vault/$(VAULT_VERSION)/vault_$(VAULT_VERSION)_$(VAULT_OS)_$(VAULT_ARCH).zip
	# Verify the download against HashiCorp's published checksums before executing it.
	curl -fsSL -o .tools/vault-$(VAULT_VERSION).sums https://releases.hashicorp.com/vault/$(VAULT_VERSION)/vault_$(VAULT_VERSION)_SHA256SUMS
	cd .tools && grep "vault_$(VAULT_VERSION)_$(VAULT_OS)_$(VAULT_ARCH).zip" vault-$(VAULT_VERSION).sums \
		| sed 's|vault_$(VAULT_VERSION)_$(VAULT_OS)_$(VAULT_ARCH).zip|vault-$(VAULT_VERSION).zip|' \
		| (sha256sum -c - 2>/dev/null || shasum -a 256 -c -)
	unzip -o -p .tools/vault-$(VAULT_VERSION).zip vault > $@ && chmod +x $@ && rm .tools/vault-$(VAULT_VERSION).zip .tools/vault-$(VAULT_VERSION).sums

clean:
	rm -rf .tools

.PHONY: all build test test-vault clean
