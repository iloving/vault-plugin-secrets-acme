package acme

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCerts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: pathStringCerts + "/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:     framework.TypeString,
				Required: true,
			},
			"common_name": {
				Type:     framework.TypeString,
				Required: true,
			},
			"alternative_names": {
				Type: framework.TypeCommaStringSlice,
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

func (b *backend) certCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}

	names := getNames(data)

	path := pathStringRoles + "/" + data.Get("role").(string)
	r, err := getRole(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return logical.ErrorResponse("This role does not exists."), nil
	}
	if err = validateNames(b, r, names); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	path = pathStringAccounts + "/" + r.Account
	a, err := getAccount(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}
	// Lookup cache
	cacheKey, err := getCacheKey(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache key: %v", err)
	}

	var cert *certificate.Resource

	// Let's first check the cache to see if a cert already exists
	if !r.DisableCache {
		b.cache.Lock()
		defer b.cache.Unlock()
		b.Logger().Debug("Look in the cache for a saved cert")
		ce, err := b.cache.Read(ctx, req.Storage, r, cacheKey)
		if err != nil {
			return nil, err
		}
		if ce == nil {
			b.Logger().Debug("Certificate not found in the cache")
		} else {
			cert = ce.Certificate()
		}
	}

	// If we did not find a cert, we have to request one
	if cert == nil {
		b.Logger().Debug("Contacting the ACME provider to get a new certificate")
		cert, err = getCertFromACMEProvider(ctx, b.Logger(), req, a, names)
		if err != nil {
			return logical.ErrorResponse("Failed to validate certificate signing request: %s", err), err
		}
		// Save the cert in the cache for the next request
		if !r.DisableCache {
			err = b.cache.Create(ctx, req.Storage, r, cacheKey, cert)
			if err != nil {
				return nil, err
			}
		}
	}

	s, err := b.getSecret(path, cacheKey, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create the secret: %v", err)
	}

	return s, nil
}

func getCacheKey(r *role, data *framework.FieldData) (string, error) {
	rolePath, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshall role: %v", err)
	}

	d := make(map[string]interface{})
	for key := range data.Schema {
		d[key] = data.Get(key)
	}
	dataPath, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("failed to marshall data: %v", err)
	}

	key := string(rolePath) + string(dataPath)
	hashedKey := sha256.Sum256([]byte(key))

	return fmt.Sprintf("%s%x", cachePrefix, hashedKey), nil
}
func getPrivateKeyType(privateKey string) (string, error) {
	re := regexp.MustCompile(`^-----BEGIN\s+(\w+)\s+PRIVATE KEY-----`)
	match := re.FindStringSubmatch(privateKey)
	if len(match) > 1 {
		return strings.ToLower(match[1]), nil
	}

	return "", fmt.Errorf("unable to extract private key type from %q", privateKey)
}
func getSerialNumberFromBytes(certBytes []byte) (string, error) {

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("error while obtaining serial number: %w", err)
	}

	serialNumberBytes := certificate.SerialNumber.Bytes()
	serialNumberHex := hex.EncodeToString(serialNumberBytes)
	output := ""
	for i := 0; i < len(serialNumberHex); i++ {
		output += string(serialNumberHex[i])
		if i < len(serialNumberHex)-1 && i%2 == 1 {
			output += ":"
		}
	}
	return output, nil
}
func (b *backend) getSecret(accountPath, cacheKey string, cert *certificate.Resource) (*logical.Response, error) {
	// Use the helper to create the secret
	b.Logger().Debug("Preparing response")
	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		return nil, err
	}

	notBefore := certs[0].NotBefore
	notAfter := certs[0].NotAfter

	privateKeyType, err := getPrivateKeyType(string(cert.PrivateKey))
	if err != nil {
		return nil, err
	}
	serialNumber, err := getSerialNumberFromBytes(cert.Certificate)
	if err != nil {
		return nil, err
	}
	s := b.Secret(secretCertType).Response(
		map[string]interface{}{
			certFieldDomain:         cert.Domain,
			certFieldUrl:            cert.CertStableURL,
			certFieldPrivateKey:     string(cert.PrivateKey),
			certFieldPrivateKeyType: privateKeyType,
			certFieldCertificate:    string(cert.Certificate),
			certFieldIssuingCA:      string(cert.IssuerCertificate),
			certFieldCAChain:        []string{string(cert.IssuerCertificate)},
			certFieldExpiration:     notAfter.Unix(),
			certFieldNotBefore:      notBefore.String(),
			certFieldNotAfter:       notAfter.String(),
			certFieldSerial:         serialNumber,
		},
		// this will be used when revoking the certificate
		map[string]interface{}{
			"account":            accountPath,
			certFieldCertificate: string(cert.Certificate),
			certFieldUrl:         cert.CertStableURL,
			"cache_key":          cacheKey,
		})

	s.Secret.MaxTTL = time.Until(notAfter)

	return s, nil
}

func getNames(data *framework.FieldData) []string {
	altNames := data.Get("alternative_names").([]string)
	names := make([]string, len(altNames)+1)
	names[0] = data.Get("common_name").(string)
	for i, n := range altNames {
		names[i+1] = n
	}

	return names
}

func validateNames(b logical.Backend, r *role, names []string) error {
	b.Logger().Debug("Validate names", "role", r, "names", names)

	isSubdomain := func(domain, root string) bool {
		return strings.HasSuffix(domain, "."+root)
	}

	for _, name := range names {
		var valid bool
		for _, domain := range r.AllowedDomains {
			if (domain == name && r.AllowBareDomains) ||
				(isSubdomain(name, domain) && r.AllowSubdomains) {
				valid = true
			}
		}
		if !valid {
			return fmt.Errorf("'%s' is not an allowed domain", name)
		}
	}

	return nil
}
