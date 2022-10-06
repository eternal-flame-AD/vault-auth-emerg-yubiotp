package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/gomail.v2"
)

func (b *backend) sendNotificationEmail(ctx context.Context, req *logical.Request, key *keyState) (sent bool, err error) {
	var config *emergencyOTPConfig
	config, err = b.config(ctx, req.Storage)
	if config == nil {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if config.SMTPHost == "" {
		return false, nil
	}

	msg := gomail.NewMessage()
	msg.SetHeader("From", config.SMTPFrom)
	msg.SetHeader("To", config.SMTPTo)
	msg.SetHeader("Subject", "Emergency OTP Key '"+key.Name+"' was used on Vault")
	msg.SetBody("text/plain", fmt.Sprintf(
		"Emergency OTP Key '%s' was used on Vault at %s.\n"+
			"Access would be authorized after %d minutes./\n"+
			"Use \"vault write auth/emerg-yubiotp/key/%s next_eligible_time=-1\" to disable this key.",
		key.Name, req.Connection.RemoteAddr, key.Delay, key.Name))
	if err := gomail.NewDialer(config.SMTPHost, config.SMTPPort, config.SMTPUsername, config.SMTPPassword).DialAndSend(msg); err != nil {
		return false, err
	}

	return true, nil
}
