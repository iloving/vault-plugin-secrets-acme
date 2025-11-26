package acme

// The field names to use for certificates.
const secretFieldDomain = "domain"
const secretFieldUrl = "url"
const secretFieldPrivateKey = "private_key"
const secretFieldPrivateKeyType = "private_key_type"
const secretFieldCertificate = "certificate"
const secretFieldIssuingCA = "issuing_ca"
const secretFieldCAChain = "ca_chain"
const secretFieldNotBefore = "not_before"
const secretFieldNotAfter = "not_after"
const secretFieldExpiration = "expiration"
const secretFieldSerial = "serial_number"
const secretFieldAccount = "account"
const secretFieldCacheKey = "cache_key"

// Vault secret type
const secretCertType = "cert"

// Path strings
const pathStringCerts = "certs"
const pathStringIssue = "issue"
const pathStringRoles = "roles"
const pathStringAccounts = "accounts"

// paramStrings
const paramStringDomain = "domain"
const paramStringRole = "role"
const paramStringAccount = "account"
const paramStringCommonName = "common_name"
const paramStringAllowedDomains = "allowed_domains"
const paramStringAllowBareDomains = "allow_bare_domains"
const paramStringAllowSubdomains = "allow_subdomains"
const paramStringDisableCache = "disable_cache"
const paramStringCacheForRatio = "cache_for_ratio"
const paramStringAltNames = "alt_names"
const paramStringIPSANS = "ip_sans"
const paramStringURISANS = "uri_sans"
const paramStringTTL = "ttl"
const paramStringCSR = "csr"
