package acme

import (

	//	"github.com/ctx42/testing/pkg/dump"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathIssue(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: pathStringIssue + "/" + framework.GenericNameRegex(paramStringRole),
		Fields: map[string]*framework.FieldSchema{
			paramStringRole: {
				Type:     framework.TypeString,
				Required: true,
			},
			paramStringCommonName: {
				Type:     framework.TypeString,
				Required: true,
			},
			paramStringAltNames: {
				Type: framework.TypeCommaStringSlice,
			},
			paramStringIPSANS: {
				Type: framework.TypeCommaStringSlice,
			},
			paramStringURISANS: {
				Type: framework.TypeCommaStringSlice,
			},
			paramStringTTL: {
				Type: framework.TypeString,
			},
			paramStringCSR: {
				Type: framework.TypeString,
			},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.certCreate,
			},
		},
	}
}
