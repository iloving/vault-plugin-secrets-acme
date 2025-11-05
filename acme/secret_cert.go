package acme

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secretCert(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretCertType,
		Fields: map[string]*framework.FieldSchema{
			certFieldDomain: {
				Type: framework.TypeString,
			},
			certFieldUrl: {
				Type: framework.TypeString,
			},
			certFieldPrivateKey: {
				Type: framework.TypeString,
			},
			certFieldPrivateKeyType: {
				Type: framework.TypeString,
			},
			certFieldCertificate: {
				Type: framework.TypeString,
			},
			certFieldIssuingCA: {
				Type: framework.TypeString,
			},
			certFieldCAChain: {
				Type: framework.TypeString,
			},
			certFieldNotBefore: {
				Type: framework.TypeString,
			},
			certFieldExpiration: {
				Type: framework.TypeInt,
			},
			certFieldNotAfter: {
				Type: framework.TypeString,
			},
		},
		Renew:  b.certRenew,
		Revoke: b.certRevoke,
	}
}

func (b *backend) certRenew(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	// I'm not really sure about this
	resp.Secret.TTL = resp.Secret.TTL + req.Secret.Increment
	return resp, nil
}

func (b *backend) certRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.cache.Lock()
	defer b.cache.Unlock()
	cacheKey := req.Secret.InternalData["cache_key"].(string)

	ce, err := b.cache.Read(ctx, req.Storage, nil, cacheKey)
	if err != nil {
		return nil, err
	}

	ce.Users--
	if ce.Users > 0 {
		err = ce.Save(ctx, req.Storage, cacheKey)
		if err != nil {
			return nil, err
		}
	} else {
		// If the last user asked for the lease to be terminated we revoke the cert
		b.Logger().Debug("Removing cached cert", "key", cacheKey)
		err = b.cache.Delete(ctx, req.Storage, cacheKey)
		if err != nil {
			return nil, fmt.Errorf("failed to remove cache entry: %v", err)
		}

		accountPath := req.Secret.InternalData["account"].(string)
		a, err := getAccount(ctx, req.Storage, accountPath)
		if err != nil {
			return nil, err
		}
		if a == nil {
			return nil, fmt.Errorf("error while revoking certificate: user not found")
		}
		client, err := a.getClient()
		if err != nil {
			return logical.ErrorResponse("Failed to get LEGO client."), err
		}
		cert := req.Secret.InternalData[certFieldCertificate].(string)
		err = client.Certificate.Revoke([]byte(cert))
		if err != nil {
			return nil, fmt.Errorf("failed to revoke cert: %v", err)
		}
	}

	return nil, nil
}
