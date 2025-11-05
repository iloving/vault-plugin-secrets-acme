package acme

// The field names to use for certificates.
const certFieldDomain = "domain"
const certFieldUrl = "url"
const certFieldPrivateKey = "private_key"
const certFieldPrivateKeyType = "private_key_type"
const certFieldCertificate = "certificate"
const certFieldIssuingCA = "issuing_ca"
const certFieldCAChain = "ca_chain"
const certFieldNotBefore = "not_before"
const certFieldNotAfter = "not_after"
const certFieldExpiration = "expiration"
const certFieldSerial = "serial_number"

// Vault secret type
const secretCertType = "cert"

// Path strings
const pathStringCerts = "certs"
const pathStringRoles = "roles"
const pathStringAccounts = "accounts"
