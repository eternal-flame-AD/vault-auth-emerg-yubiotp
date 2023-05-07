package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if b.yubiAuth == nil {
		return logical.ErrorResponse("yubiAuth is not initialized"), logical.ErrPermissionDenied
	}

	// validate first to prevent bruteforcing
	yr, ok, err := b.yubiAuth.Verify(strings.TrimSpace(d.Get("otp_response").(string)))
	if err != nil {
		return logical.ErrorResponse("%v", err), logical.ErrPermissionDenied
	} else if !ok {
		return logical.ErrorResponse("yubikey verification failed"), logical.ErrPermissionDenied
	}
	sessionUseCounter := yr.GetResultParameter("sessionuse")
	sessionCounter := yr.GetResultParameter("sessioncounter")
	keyPublicId := yr.GetResultParameter("otp")[:12]

	keyFound := false
	var key keyState

	// look up if the key is on record
	entry, err := req.Storage.Get(ctx, "key-name-by-id/"+keyPublicId)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		keyName := string(entry.Value)
		entry, err = req.Storage.Get(ctx, "key/"+keyName)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			keyFound = true
			if err := entry.DecodeJSON(&key); err != nil {
				return nil, err
			}
		}
	}

	// key is not on file
	if !keyFound {
		return logical.ErrorResponse("sorry, this key is not allowed"), logical.ErrPermissionDenied
	}

	if key.NextEligibleTime < 0 {
		return logical.ErrorResponse("sorry, this key is disabled"), logical.ErrPermissionDenied
	}

	keyHumanName := fmt.Sprintf("emergency-key-%s-%s", key.Name, keyPublicId)
	keyAlias := keyHumanName
	if key.Alias != "" {
		keyAlias = key.Alias
	}

	// eligible to login
	if key.NextEligibleTime > 0 && time.Now().Unix() > key.NextEligibleTime {
		return &logical.Response{
			Auth: &logical.Auth{
				DisplayName: keyHumanName,
				InternalData: map[string]interface{}{
					"auth_method":           "emerg-yubiotp",
					"emerg_yubiotp_keyname": key.Name,
				},
				Policies: []string{"emerg-yubiotp", "default"},
				Metadata: map[string]string{
					"session_counter":      sessionCounter,
					"session_counter_used": sessionUseCounter,
					"yubikey_public_id":    keyPublicId,
					"yubikey_name":         key.Name,
					"yubikey_alias":        keyAlias,
				},
				LeaseOptions: logical.LeaseOptions{
					TTL:       1 * time.Hour,
					MaxTTL:    24 * time.Hour,
					Renewable: true,
				},
				Alias: &logical.Alias{
					Name: keyAlias,
				},
			},
		}, nil
	}

	nextEligibleUpdated := false
	returnMsg := ""

	// already waiting for a no-notify approval, try sending a notification again
	if key.NextEligibleTime == 0 || key.NextEligibleTime > time.Now().Add(time.Duration(key.DelayMail)*time.Minute).Unix() {
		if sent, err := b.sendNotificationEmail(ctx, req, &key); err != nil {
			returnMsg += "Email notification failed: " + err.Error() + ". \n"
		} else if sent {
			returnMsg += "Email notification sent. \n"
			key.NextEligibleTime = time.Now().Add(time.Duration(key.DelayMail) * time.Minute).Unix()
			nextEligibleUpdated = true
		}
	}

	// for some reason already waiting for a longer time but current configured delay is shorter, update the wait time
	if key.NextEligibleTime == 0 || key.NextEligibleTime > time.Now().Add(time.Duration(key.Delay)*time.Minute).Unix() {
		key.NextEligibleTime = time.Now().Add(time.Duration(key.Delay) * time.Minute).Unix()
		nextEligibleUpdated = true
	}

	entry, err = logical.StorageEntryJSON("key/"+key.Name, key)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if key.NextEligibleTime == 0 {
		return logical.ErrorResponse(returnMsg + "Unfortunately you could not be authorized at this time."), logical.ErrPermissionDenied
	}

	if nextEligibleUpdated {
		returnMsg += "Your wait time is updated.\n"
	} else {
		returnMsg += "Your wait time is not updated.\n"
	}
	return logical.ErrorResponse(
		"%sYou need to wait until %v (approx. %d mins) before you could be authorized.",
		returnMsg,
		time.Unix(key.NextEligibleTime, 0),
		(int64)(time.Until(time.Unix(key.NextEligibleTime, 0)).Minutes()),
	), logical.ErrPermissionDenied
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	keyName, ok := req.Auth.InternalData["emerg_yubiotp_keyname"].(string)
	if !ok {
		return nil, errors.New("request auth internal key data was nil, try re-authenticating")
	}

	var ks keyState
	entry, err := req.Storage.Get(ctx, "key/"+keyName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errors.New("key not found")
	}
	if err := entry.DecodeJSON(&ks); err != nil {
		return nil, err
	}

	if ks.NextEligibleTime < 0 {
		return logical.ErrorResponse("sorry, this key is disabled"), logical.ErrPermissionDenied
	}

	if ks.NextEligibleTime > 0 && time.Now().Unix() > ks.NextEligibleTime {
		return framework.LeaseExtend(30*time.Second, 60*time.Minute, b.System())(ctx, req, d)
	}

	return logical.ErrorResponse("sorry, you are not eligible to renew your lease"), logical.ErrPermissionDenied
}
