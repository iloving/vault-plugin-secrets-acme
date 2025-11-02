# Vault Secrets Plugin for ACME Certificaates
[![Run tests](https://github.com/iloving/vault-plugin-secrets-acme/actions/workflows/test.yml/badge.svg)](https://github.com/iloving/vault-plugin-secrets-acme/actions/workflows/test.yml)

This plugin wraps the [LEGO](https://github.com/go-acme/lego) library into a secrets engine plugin for [Vault](https://www.vaultproject.io/). so that users and applications can dynamically generate TLS certificates validated by an [ACME provider](https://tools.ietf.org/html/rfc8555) such as [Let's Encrypt](https://letsencrypt.org/). 

This project is the latest in a succession of forks:
* Original: https://github.com/remilapeyre/vault-acme/ (Discussed here: https://github.com/hashicorp/vault/issues/4950)
* Forked with some updates:  https://github.com/Boostport/vault-plugin-secrets-acme
* Forked again with more updates:  https://github.com/SierraSoftworks/vault-plugin-secrets-acme

## Download Vault ACME
Binary releases can be downloaded at https://github.com/iloving/vault-plugin-secrets-acme/releases.

## Verify Binaries
The checksum for the binaries are signed with cosign. To verify the binaries, download the following files (where
`${VERSION}` is the version of the release):
- `vault-plugin-secrets-acme_${VERSION}_checksums.txt`
- `vault-plugin-secrets-acme_${VERSION}_checksums.txt.pem`
- `vault-plugin-secrets-acme_${VERSION}_checksums.txt.sig`

Then download the release binaries you need. Here, we just download the linux amd64 binary:
-  `vault-plugin-secrets-acme_${VERSION}_linux_amd64`

Then run the following commands to verify the checksums and signature:
```sh
# Verify checksum signature
$ cosign verify-blob --signature vault-plugin-secrets-acme_${VERSION}_checksums.txt.sig --certificate vault-plugin-secrets-acme_${VERSION}_checksums.txt.pem vault-plugin-secrets-acme_${VERSION}_checksums.txt --certificate-identity "https://github.com/Boostport/vault-plugin-secrets-acme/.github/workflows/release.yml@refs/tags/v${VERSION}" --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify checksum with binaries
$ sha256sum -c vault-plugin-secrets-acme_${VERSION}_checksums.txt
```

## Installation

1. Copy the binary to the [`Vault plugin directory`](https://www.vaultproject.io/docs/configuration/#plugin_directory)
1. If you are running Vault in a docker container and MLOCK is enabled, you need to set the mlock flag for the plugin as well:

```sh
sudo setcap cap_ipc_lock=+ep /vault/plugins/vault-plugin-secrets-acme
```

### Registration
Vault requires a checksum when registering a plugin. Instructions for obtaining the checksum can be found [here](https://support.hashicorp.com/hc/en-us/articles/9686843138963-Get-the-SHA-256-checksum-for-Vault-plugin).

The below command registers the plugin under the alias name `acme`

```
vault plugin register -command=vault-plugin-secrets-acme \
-sha256=<checksum> \
secret acme 
```

If required, the plugin can be registered multiple times under different names.  eg:
```
vault plugin register -command=vault-plugin-secrets-acme \
-sha256=<checksum> \
secret acme1

vault plugin register -command=vault-plugin-secrets-acme \
-sha256=<checksum> \
secret acmeN 
```

## Usage
The documentation is available at [`USAGE.md`](./USAGE.md).

## Limitations/Bugs

### provider_configuration only supports a single key-pair

Due to a bug in the Vault SDK, the current method of passing provider configuration details is limited to a [single KV pair](https://github.com/hashicorp/vault/issues/31621).  

This means when you are adding the account configuration, for example:
``` sh
vault write test/accounts/le-staging \
	contact=my_email@example.com \
	server_url=https://acme-staging-v02.api.letsencrypt.org/directory \
	terms_of_service_agreed=true \
	provider=webnamesca \
	provider_configuration='WEBNAMESCA_API_USER="xxx",WEBNAMESCA_API_KEY="yyy"'
```
the configuration will have `WEBNAMESCA_API_USER: "xxx,WEBNAMESCA_API_KEY=yyy"` instead of the expected `WEBNAMESCA_API_USER:"xxx", WEBNAMESCA_API_KEY:"yyy"`

Because LEGO uses environment variables for provider configuration, if your desired DNS provider uses more than one parameter, the current workaround is to use -env arguments when registering the plugin to pass the additional parameters. eg:
```
vault plugin register -command=vault-plugin-secrets-acme \
-sha256=<checksum> \
-env=WEBNAMESCA_API_USER=my_provider_userid \
-env=WEBNAMESCA_API_KEY=my_provider_api_key \
secret acme 
```
Keep in mind that this will cause the variables to be passed to _all_ invocations of that plugin registration.  This means if need to support multiple accounts with the same provider, you will need to register multiple instances of the plugin using different names, each with it's own env variables.

### EXEC provider does not work
The EXEC DNS provider works by calling an external command.  This fails with exit code 127.  This is likely a restriction imposed Vault but investigation needs to be done.

## Tests
The unit tests will use the `pebble` ACME test server and `pebble-challtestsrv`.
They can be downloaded at https://github.com/letsencrypt/pebble and must be
present in `$PATH`.

The unit tests can be run with:

```bash
$ make test
```

The acceptance tests needs Vault in addition to `pebble` and `pebble-challtestsrv`.

When `vault` is present in `$PATH` the acceptance tests can be run with:

```bash
$ make testacc
```
