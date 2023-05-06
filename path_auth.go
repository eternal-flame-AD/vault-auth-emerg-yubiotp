package main

import (
	"context"
	"errors"
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

	// eligible to login
	if key.NextEligibleTime > 0 && time.Now().Unix() > key.NextEligibleTime {
		return &logical.Response{
			Auth: &logical.Auth{
				DisplayName: "Emergency Yubikey " + keyPublicId,
				InternalData: map[string]interface{}{
					"auth_method": "emerg-yubiotp",
				},
				Policies: []string{"emerg-yubiotp", "default"},
				Metadata: map[string]string{
					"session_counter":      sessionCounter,
					"session_counter_used": sessionUseCounter,
					"yubikey_public_id":    keyPublicId,
				},
				LeaseOptions: logical.LeaseOptions{
					TTL:       1 * time.Hour,
					MaxTTL:    24 * time.Hour,
					Renewable: true,
				},
				Alias: &logical.Alias{
					Name: "Emergency Key " + keyPublicId,
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
		"%sYou need to wait until %v (approx %v mins) before you could be authorized.",
		returnMsg,
		time.Unix(key.NextEligibleTime, 0),
		time.Until(time.Unix(key.NextEligibleTime, 0)).Minutes(),
	), logical.ErrPermissionDenied
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	return framework.LeaseExtend(30*time.Second, 60*time.Minute, b.System())(ctx, req, d)
}
