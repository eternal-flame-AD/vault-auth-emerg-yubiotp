package main

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type keyState struct {
	Name             string `json:"name"`
	Alias            string `json:"alias"`
	PublicID         string `json:"public_id"`
	NextEligibleTime int64  `json:"next_eligible_time"`

	Delay     int64 `json:"delay"`
	DelayMail int64 `json:"delay_mail"`
}

func (b *backend) pathKeys() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `key/(?P<name>.+)`,
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key",
				},
				"alias": {
					Type:        framework.TypeString,
					Description: "Alias to be assigned",
				},
				"public_id": {
					Type:        framework.TypeString,
					Description: "Public ID of the key",
				},
				"delay": {
					Type:        framework.TypeInt,
					Description: "Delay in minutes before the key can be authorized",
				},
				"delay_mail": {
					Type:        framework.TypeInt,
					Description: "Delay in minutes before the key can be authorized if mail notification was sent",
				},
				"next_eligible_time": {
					Type:        framework.TypeString,
					Description: "The next time the key is eligible to be used. unix timestamp or +10m",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeyWrite,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeyWrite,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKeyRead,
				},
			}},
		{
			Pattern: `key`,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKeyList,
				},
			},
		},
	}
}

func (b *backend) pathKeyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	var ks keyState
	ks.Name = name
	ks.Delay = -1
	ks.DelayMail = -1

	entry, err := req.Storage.Get(ctx, "key/"+name)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		if err := entry.DecodeJSON(&ks); err != nil {
			return nil, err
		}
	}

	alias := data.Get("alias").(string)
	if alias != "" {
		ks.Alias = alias
	}
	publicID := strings.TrimSpace(data.Get("public_id").(string))
	if publicID != "" {
		ks.PublicID = publicID
	}
	if d, err := modhexDecode(ks.PublicID); err != nil {
		return logical.ErrorResponse("invalid public ID %s: %s", err.Error()), nil
	} else if len(d) < 6 {
		return logical.ErrorResponse("invalid public ID: must be at least 12 characters (6 bytes modhex)"), nil
	}
	ks.PublicID = ks.PublicID[:12]
	delay, ok := data.GetOk("delay")
	if ok {
		ks.Delay = int64(delay.(int))
	}
	delaymail, ok := data.GetOk("delay_mail")
	if ok {
		ks.DelayMail = int64(delaymail.(int))
	}

	nextEligibleTime := data.Get("next_eligible_time").(string)
	nextEligibleTimeUnix := ks.NextEligibleTime
	if strings.HasPrefix(nextEligibleTime, "+") && len(nextEligibleTime) > 1 {
		d, err := time.ParseDuration(nextEligibleTime[1:])
		if err != nil {
			return nil, err
		}
		nextEligibleTimeUnix = time.Now().Add(d).Unix()
	} else if ts, err := strconv.ParseInt(nextEligibleTime, 10, 64); err == nil {
		nextEligibleTimeUnix = ts
	} else if nextEligibleTime != "" {
		return logical.ErrorResponse("unvalid next_eligible_time %s", nextEligibleTime), err
	}
	ks.NextEligibleTime = nextEligibleTimeUnix

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "key-name-by-id/" + ks.PublicID,
		Value: []byte(name),
	})
	if err != nil {
		return nil, err
	}

	entry, err = logical.StorageEntryJSON("key/"+name, ks)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "key/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("could not find key named %s", name), nil
	}
	var ks keyState
	if err := entry.DecodeJSON(&ks); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"name":               name,
			"alias":              ks.Alias,
			"public_id":          ks.PublicID,
			"delay":              ks.Delay,
			"delay_mail":         ks.DelayMail,
			"next_eligible_time": ks.NextEligibleTime,
		},
	}, nil

}

func (b *backend) pathKeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "key/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}
