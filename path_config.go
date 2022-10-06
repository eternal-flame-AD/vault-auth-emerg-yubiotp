package main

import (
	"context"
	"strings"

	"github.com/eternal-flame-AD/yubigo"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/gomail.v2"
)

const confHelpSynopsis = `Emergency OTP backend.`
const confHelpDescription = `Emergency OTP backend.`

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"yubiauth_client_id": {
				Type:        framework.TypeString,
				Description: "YubiAuth client ID",
			},
			"yubiauth_client_key": {
				Type:        framework.TypeString,
				Description: `YubiAuth client key`,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"smtp_host": {
				Type:        framework.TypeString,
				Description: `SMTP host`,
			},
			"smtp_port": {
				Type:        framework.TypeInt,
				Description: `SMTP port`,
			},
			"smtp_username": {
				Type:        framework.TypeString,
				Description: `SMTP username`,
			},
			"smtp_password": {
				Type:        framework.TypeString,
				Description: `SMTP password`,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"smtp_from": {
				Type:        framework.TypeString,
				Description: `SMTP from`,
			},
			"smtp_to": {
				Type:        framework.TypeString,
				Description: `SMTP to`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
		},

		HelpSynopsis:    confHelpSynopsis,
		HelpDescription: confHelpDescription,
	}
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if config, err := b.config(ctx, req.Storage); err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"yubiauth_client_id":  config.YubiAuthClientId,
				"yubiauth_client_key": strings.Repeat("*", 8),
				"smtp_host":           config.SMTPHost,
				"smtp_port":           config.SMTPPort,
				"smtp_username":       config.SMTPUsername,
				"smtp_password":       strings.Repeat("*", 8),
				"smtp_from":           config.SMTPFrom,
				"smtp_to":             config.SMTPTo,
			},
		}, nil
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	fieldYubiAuthClientId, ok := data.GetOk("yubiauth_client_id")
	if ok {
		config.YubiAuthClientId = fieldYubiAuthClientId.(string)
	}
	fieldYubiAuthClientKey, ok := data.GetOk("yubiauth_client_key")
	if ok {
		config.YubiAuthClientKey = fieldYubiAuthClientKey.(string)
	}
	fieldSMTPHost, ok := data.GetOk("smtp_host")
	if ok {
		config.SMTPHost = fieldSMTPHost.(string)
	}
	fieldSMTPPort, ok := data.GetOk("smtp_port")
	if ok {
		config.SMTPPort = fieldSMTPPort.(int)
	}
	fieldSMTPUsername, ok := data.GetOk("smtp_username")
	if ok {
		config.SMTPUsername = fieldSMTPUsername.(string)
	}
	fieldSMTPPassword, ok := data.GetOk("smtp_password")
	if ok {
		config.SMTPPassword = fieldSMTPPassword.(string)
	}
	fieldSMTPFrom, ok := data.GetOk("smtp_from")
	if ok {
		config.SMTPFrom = fieldSMTPFrom.(string)
	}
	fieldSMTPTo, ok := data.GetOk("smtp_to")
	if ok {
		config.SMTPTo = fieldSMTPTo.(string)
	}

	if config.SMTPHost != "" {
		d, err := gomail.NewDialer(config.SMTPHost, config.SMTPPort, config.SMTPUsername, config.SMTPPassword).Dial()
		if d != nil {
			defer d.Close()
		}
		if err != nil {
			return logical.ErrorResponse("SMTP config not valid: %v", err), nil
		}
	}

	b.yubiAuth, err = yubigo.NewYubiAuth(config.YubiAuthClientId, config.YubiAuthClientKey)
	if err != nil {
		return nil, err
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}
