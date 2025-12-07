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

	//	"github.com/ctx42/testing/pkg/dump"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCerts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: pathStringCerts + "/" + framework.GenericNameRegex(paramStringRole),
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

func (b *backend) certCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := data.Validate(); err != nil {
		return nil, err
	}
	path := pathStringRoles + "/" + data.Get(paramStringRole).(string)
	r, err := getRole(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return logical.ErrorResponse("This role does not exists."), nil
	}

	path = pathStringAccounts + "/" + r.Account
	a, err := getAccount(ctx, req.Storage, path)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("This account does not exists"), nil
	}
	//b.Logger().Trace("Data received for certificate creation: " + dump.Any(data))

	if v, ok := data.GetOk(paramStringIPSANS); ok {
		if arr, _ := v.([]string); len(arr) > 0 {
			return logical.ErrorResponse("ip_sans and uri_sans are not supported"), nil
		}
	}
	if v, ok := data.GetOk(paramStringURISANS); ok {
		if arr, _ := v.([]string); len(arr) > 0 {
			return logical.ErrorResponse("ip_sans and uri_sans are not supported"), nil
		}
	}

	// Lookup cache
	b.Logger().Trace("Generating cache key")
	cacheKey, err := getCacheKey(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get cache key: %v", err)
	}
	b.Logger().Trace("Cache key generated: " + cacheKey)

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

	if cert == nil {
		_, hasCSR := data.GetOk(paramStringCSR)
		if hasCSR {
			b.Logger().Info("CSR found, using it to create the certificate.  Ignoring alt_names and common_name.")
			cert, err = b.certCreateFromCSR(ctx, req, data, r, a)
		} else {
			cert, err = b.certCreateDefault(ctx, req, data, r, a)
		}
		if err != nil {
			return logical.ErrorResponse("certificate request failed: %s", err), err
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
func (b *backend) certCreateDefault(ctx context.Context, req *logical.Request, data *framework.FieldData, r *role, a *account) (*certificate.Resource, error) {
	var err error

	b.Logger().Trace("Compiling a list of hostnames for the certificate")
	names := getNames(data)
	//b.Logger().Trace("Validating names: " + dump.Any(names))
	b.Logger().Trace("Validating names: " + strings.Join(names, ","))
	if err = validateNames(b, r, names); err != nil {
		return nil, err
	}

	b.Logger().Debug("Contacting the ACME provider to get a new certificate")

	cert, err := getCertFromACMEProvider(ctx, b.Logger(), req, a, names, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get a new certificate: %w", err)
	}

	return cert, nil

}
func (b *backend) certCreateFromCSR(ctx context.Context, req *logical.Request, data *framework.FieldData, r *role, a *account) (*certificate.Resource, error) {
	var err error
	var certificateRequest *x509.CertificateRequest
	var cert *certificate.Resource
	b.Logger().Trace("Obtaining certificate from ACME provider")
	csrData, hasCSR := data.GetOk(paramStringCSR)
	if !hasCSR {
		return nil, fmt.Errorf("somehow CSR data vanished")
	}
	certificateRequest, err = b.convertCSRDataToCertificateRequest([]byte(csrData.(string)))
	if err != nil {
		return nil, fmt.Errorf("error parsing the CSR data: %w", err)
	}

	b.Logger().Trace("Extracting names from CSR")
	names := getNamesFromCR(certificateRequest)
	if err = validateNames(b, r, names); err != nil {
		return nil, fmt.Errorf("error validating names: %w", err)
	}

	// If we did not find a cert, we have to request one
	b.Logger().Debug("Contacting the ACME provider to get a new certificate")

	cert, err = getCertFromACMEProvider(ctx, b.Logger(), req, a, names, certificateRequest)
	if err != nil {
		return nil, fmt.Errorf("error signing CSR: %w", err)
	}
	// Save the cert in the cache for the next request

	return cert, nil
}
func (b *backend) convertCSRDataToCertificateRequest(csrData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}
	// Parse the CSR string into a CertificateRequest object
	certificateRequest, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	return certificateRequest, nil
}
func getCacheKey(r *role, data *framework.FieldData) (string, error) {
	// Build cache key from: role account, common name, alt names, and CSR
	cacheData := map[string]interface{}{
		"account":     r.Account,
		"common_name": data.Get(paramStringCommonName),
		"alt_names":   data.Get(paramStringAltNames),
		"csr":         data.Get(paramStringCSR),
	}

	dataPath, err := json.Marshal(cacheData)
	if err != nil {
		return "", fmt.Errorf("failed to marshall cache data: %v", err)
	}

	hashedKey := sha256.Sum256(dataPath)
	return fmt.Sprintf("%s%x", cachePrefix, hashedKey), nil
}

func (b *backend) getPrivateKeyType(privateKey string) (string, error) {
	re := regexp.MustCompile(`^-----BEGIN\s+(\w+)\s+PRIVATE KEY-----`)
	match := re.FindStringSubmatch(privateKey)
	if len(match) > 1 {
		return strings.ToLower(match[1]), nil
	}

	return "", fmt.Errorf("unable to extract private key type from %q", privateKey)
}

func (b *backend) getCertificateFromBytes(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error while obtaining serial number: %w", err)
	}
	return certificate, nil
}

func (b *backend) getSerialNumberFromCertificate(certBytes []byte) (string, error) {

	certificate, err := b.getCertificateFromBytes(certBytes)
	if err != nil {
		return "", err
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
	var err error
	var privateKeyType string
	// Use the helper to create the secret
	b.Logger().Debug("Preparing response")
	certs, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		return nil, err
	}

	notBefore := certs[0].NotBefore
	notAfter := certs[0].NotAfter

	privateKeyType = ""
	if cert.PrivateKey != nil {
		privateKeyType, err = b.getPrivateKeyType(string(cert.PrivateKey))
		if err != nil {
			return nil, err
		}
	}
	serialNumber, err := b.getSerialNumberFromCertificate(cert.Certificate)
	if err != nil {
		return nil, err
	}
	s := b.Secret(secretCertType).Response(
		map[string]interface{}{
			secretFieldDomain:         cert.Domain,
			secretFieldUrl:            cert.CertStableURL,
			secretFieldPrivateKey:     string(cert.PrivateKey),
			secretFieldPrivateKeyType: privateKeyType,
			secretFieldCertificate:    string(cert.Certificate),
			secretFieldIssuingCA:      string(cert.IssuerCertificate),
			secretFieldCAChain:        []string{string(cert.IssuerCertificate)},
			secretFieldExpiration:     notAfter.Unix(),
			secretFieldNotBefore:      notBefore.String(),
			secretFieldNotAfter:       notAfter.String(),
			secretFieldSerial:         serialNumber,
		},
		// this will be used when revoking the certificate
		map[string]interface{}{
			secretFieldAccount:     accountPath,
			secretFieldCertificate: string(cert.Certificate),
			secretFieldUrl:         cert.CertStableURL,
			secretFieldCacheKey:    cacheKey,
		})

	s.Secret.MaxTTL = time.Until(notAfter)

	return s, nil
}

func getNames(data *framework.FieldData) []string {
	altNames := data.Get(paramStringAltNames).([]string)
	names := make([]string, len(altNames)+1)
	names[0] = data.Get(paramStringCommonName).(string)
	for i, n := range altNames {
		names[i+1] = n
	}

	return names
}
func getNamesFromCR(cr *x509.CertificateRequest) []string {
	names := make([]string, len(cr.DNSNames)+1)
	names[0] = cr.Subject.CommonName
	for i, n := range cr.DNSNames {
		names[i+1] = n
	}

	return names
}

func validateNames(b logical.Backend, r *role, names []string) error {
	b.Logger().Debug("Validate names", paramStringRole, r, "names", names)

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
