package main

import (
	"fmt"
	"os"

	cloudflaresecrets "github.com/arcdigital/vault-cloudflare-secret-engine"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

// Build metadata, injected by GoReleaser via -ldflags at release time.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			fmt.Printf("vault-cloudflare-secret-engine %s (commit %s, built %s)\n", version, commit, date)
			return
		}
	}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logFatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: cloudflaresecrets.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logFatal(err)
	}
}

func logFatal(err error) {
	logger := hclog.New(&hclog.LoggerOptions{})
	logger.Error("plugin shutting down", "error", err)
	os.Exit(1)
}
