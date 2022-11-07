package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/eternal-flame-AD/yubigo"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	defer (func() {
		if e := recover(); e != nil {
			os.WriteFile("/var/lib/vault/vault-plugin-secrets-yubikey.panic", []byte(fmt.Sprint(e)), 0400)
			panic(e)
		}
	})()
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		os.WriteFile("/var/lib/vault/vault-plugin-secrets-yubikey.err", []byte(err.Error()), 0400)
		log.Fatal(err)
	}
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	b.Logger().Info("backend initialized")
	return b, nil
}

type backend struct {
	*framework.Backend

	yubiAuth *yubigo.YubiAuth
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"otp_response": {
						Type:        framework.TypeString,
						Description: "cccccciicfrunbhihbdvttjdernrtceibvrhvkbkkrkj",
						DisplayAttrs: &framework.DisplayAttributes{
							Name: "Yubikey OTP Response",
						},
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			},
			b.pathConfig(),
		},
		InitializeFunc: func(ctx context.Context, req *logical.InitializationRequest) (err error) {
			if conf, errC := b.config(ctx, req.Storage); err != nil {
				return errC
			} else if conf.YubiAuthClientId != "" {
				b.yubiAuth, err = yubigo.NewYubiAuth(conf.YubiAuthClientId, conf.YubiAuthClientKey)
			}
			return
		},
	}
	b.Backend.Paths = append(b.Backend.Paths, b.pathKeys()...)
	return &b
}
