---
layout: "docs"
page_title: "ACME - Secrets Engines"
sidebar_title: "ACME (Certificates)"
sidebar_current: "docs-secrets-acme"
description: |-
  The ACME secrets engine for Vault generates TLS certificates signed by an ACME CA.
---

# ACME Vault Secrets Engine

The ACME secret engine generates X.509 certificates signed by a Certificate
Authority using the Automated Certificate Management Environment (ACME) standard.

With this secrets engine, services can get certificates that can be presented to
end users and that clients will accept. Currently only Let's Encrypt implement
the ACME standard.

-> **NOTE:** The directory URLs in all examples in this provider reference Let's
  Encrypt's staging server endpoint. For production use, change the directory
  URLs to the production endpoints, which can be found [here](https://letsencrypt.org/docs/acme-protocol-updates/).

## Supported challenges

When requesting a certificate to an ACME provider, the provider tries to validate
that the user controls the domains names using challenges.

The ACME plugin supports the DNS-01 challenge type.  Other challenges still exist in the code base but they are deprecated.

- **DNS-01 challenge:** the DNS-01 challenge confirms that you control the DNS
  for the domain name. This challenge is natively supported by the ACME secret
  engine which will automatically create the appropriate records. The supported
  DNS providers and their configuration is documented in the
  [DNS providers](https://go-acme.github.io/lego/dns/index.html) documentation.


## Configuration

1. Enable the ACME secrets engine:
    ```bash
    $ vault secrets enable <plugin_name>
    Success! Enabled the acme secrets engine at: <plugin_name>/
    ```

    Example:
    ```bash
    $ vault secrets enable acme
    Success! Enabled the acme secrets engine at: acme/
    ```

    By default, the secrets engine will mount at the name of the engine. To
    enable the secrets engine at a different path, use the `-path` argument. 
    ```bash
    $ vault secrets enable -path=<secret_path> <plugin_name>
    Success! Enabled the acme secrets engine at: <secret_path>/
    ```   
    
    Example:
    ```bash
    $ vault secrets enable -path=le_certs acme
    Success! Enabled the acme secrets engine at: le_certs/
    ```    

1. Increase the TTL by tuning the secrets engine, as specified [here](https://developer.hashicorp.com/vault/docs/troubleshoot/tune-lease-ttl).

    Note that individual roles can restrict this value to be shorter on a
    per-certificate basis. This just configures the global maximum for this
    secrets engine.

    ```bash
    $ vault secrets tune -max-lease-ttl=<time_value> <secrets_path>
    Success! Tuned the secrets engine at: secret_path/
    ```

    Let's Encrypt certificates are good for 90 days.  Best practice says to renew certificates before then, so you have time to investigate if the renewal fails.  We will set the expiry to 60 days.

    ```bash
    $ vault secrets tune -max-lease-ttl=60d acme/
    Success! Tuned the secrets engine at: acme/
    ```

1. Register an account with your ACME provider
    ```bash
    $ vault write <plugin_path>/accounts/<account_name> \
		contact=<email> \
		server_url=<acme_server_url> \
		terms_of_service_agreed=true \
		provider=lego_provider_code \
            provider_configuration=VARIABLE_NAME=VARIABLE_VALUE
    ```

    Example:
    ```bash
    $ vault write acme/accounts/lenstra \
		contact=remi@lenstra.fr \
		server_url=https://acme-staging-v02.api.letsencrypt.org/directory \
		terms_of_service_agreed=true \
		provider=cloudflare \
            provider_configuration=CLOUDFLARE_DNS_API_TOKEN=my_cloudflare_token
    Success! Data written to: acme/accounts/lenstra
    ```

    **NOTE**: provider_configuration currently only supports a single keypair. (See [README.md](./README.md#provider_configuration-only-supports-a-single-key-pair))

1. Configure a role that maps a name in Vault to a procedure for generating a
certificate. When users or machines generate credentials, they are generated
against this role:
    ```bash
    $ vault write <secret_path>/roles/<role_name> \
        account=<account_name> \
        allowed_domains=<domains_allowed> \
        allow_bare_domains=false \
        allow_subdomains=true
    Success! Data written to: <secret_path>/roles/<role_name>
    ```

    Example:
    ```text
    $ vault write acme/roles/lenstra \
        account=lenstra \
        allowed_domains=lenstra.fr \
        allow_bare_domains=false \
        allow_subdomains=true
    Success! Data written to: acme/roles/lenstra
    ```

Your plugin should now be ready to dispense certificates.

**Note**: Remember to configure appropriate policies regarding who or what can access this endpoint!

## Usage

After the secrets engine is configured and a user/machine has a Vault token with
the proper permission, it can generate credentials.

Generate a new certificate by writing to the `/certs` endpoint with the name
of the role:

    ```bash
    $ vault write <secret_path>/certs/<role_name> \
        common_name=<hostname>
    ```
    Example:
```bash
$ vault write acme/certs/lenstra.fr common_name=www.lenstra.fr

Key                 Value
---                 -----
lease_id            acme/certs/lenstra.fr/A28ijF37fn9pFASIi58fonzz
lease_duration      20m
lease_renewable     true
ca_chain            [
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
]
certificate         -----BEGIN CERTIFICATE-----...
domain              test.gandersocial.ca
expiration          1770333985
issuing_ca          -----BEGIN CERTIFICATE-----...
not_after           2026-02-05 23:26:25 +0000 UTC
not_before          2025-11-07 23:26:26 +0000 UTC
private_key         -----BEGIN RSA PRIVATE KEY-----...
private_key_type    rsa
serial_number       2c:78:a3:a5:52:17:6a:b2:7d:9e:16:77:81:15:12:71:2a:61
url                 https://acme-staging-v02.api.letsencrypt.org/acme/cert/2c78a3a552176ab27d9e1677811512712a61
```

To use a CSR, add the `csr` option:
```bash
$ vault write acme/certs/lenstra.fr common_name=www.lenstra.fr csr=@wwwlenstrafr.csr
Key                 Value
---                 -----
lease_id            acme/certs/lenstra.fr/A28ijF37fn9pFASIi58fonzz
lease_duration      20m
lease_renewable     true
ca_chain            [
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
]
certificate         -----BEGIN CERTIFICATE-----...
domain              test.gandersocial.ca
expiration          1770333985
issuing_ca          -----BEGIN CERTIFICATE-----...
not_after           2026-02-05 23:26:25 +0000 UTC
not_before          2025-11-07 23:26:26 +0000 UTC
private_key         n/a
private_key_type    n/a
serial_number       2c:78:a3:a5:52:17:6a:b2:7d:9e:16:77:81:15:12:71:2a:61
url                 https://acme-staging-v02.api.letsencrypt.org/acme/cert/2c78a3a552176ab27d9e1677811512712a61
```

Notice that a private key is not generated as you would have already made your own when creating the CSR.