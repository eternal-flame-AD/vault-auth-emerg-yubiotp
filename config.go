package main

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath string = "config"
)

type emergencyOTPConfig struct {
	YubiAuthClientId  string `json:"yubi_auth_client_id"`
	YubiAuthClientKey string `json:"yubi_auth_client_key"`

	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	SMTPFrom     string `json:"smtp_from"`
	SMTPTo       string `json:"smtp_to"`
}

func (b *backend) config(ctx context.Context, s logical.Storage) (*emergencyOTPConfig, error) {
	raw, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		defaultConfig := &emergencyOTPConfig{}
		_, err := logical.StorageEntryJSON("config", defaultConfig)
		if err != nil {
			return nil, err
		}
		return defaultConfig, nil
	}

	conf := &emergencyOTPConfig{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}

	return conf, nil
}
