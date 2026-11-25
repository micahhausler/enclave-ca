# Design and threat model

This doc covers how `enclave-ca` holds each key, what TPM attestation proves, why it exists instead of an existing tool, and what each failure costs.

## Goal

A personal root CA whose key can't be copied, where every signature needs a person present, built from as little code as possible that you have to trust.

## How the key is held

`init` creates a P-256 key with CryptoKit's [`SecureEnclave.P256.Signing.PrivateKey`](https://developer.apple.com/documentation/cryptokit/secureenclave).
Its access control is `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with `[.privateKeyUsage, .userPresence]`.

- The key is generated inside the enclave and never leaves it.
- `ca.key` holds `dataRepresentation`, a blob wrapped by this device's enclave. No other device can use it.
- No keychain item is created, so the binary needs no entitlements and no Developer ID signature; an ad-hoc signed build works.
- Each `sign` loads the key with a fresh `LAContext`, so each signature prompts. One approval never covers a second signature (tested: two signatures in one process gave two prompts).
- The Touch ID prompt text names the CN and validity being signed.

### `.userPresence` vs biometry

`.userPresence` accepts Touch ID or the login password.
It survives adding or removing fingerprints and works with the lid closed.
In exchange, someone holding the unlocked Mac and your login password can sign.

`.biometryAny` would require a finger, with no password fallback.
`.biometryCurrentSet` additionally destroys the key whenever the set of enrolled fingers changes.

The access control is fixed when the key is created.

## Mac client keys

`client-key` creates a second kind of enclave key, for a Mac's own Roles Anywhere credentials.
Like the CA key, it is non-exportable and bound to this Mac.
Never use a client key as a CA key.

### Access modes

`client-key --access MODE` picks what each use of the key needs, and the choice is fixed when the key is created.

- `none` (the default) needs nothing.
- `user-presence` needs Touch ID or the login password.
- `passcode` needs the login password.

A `none` key is the macOS equivalent of a password-less TPM key.
Any process running as you can use it without a prompt, including launchd jobs while the screen is locked, once the Mac has been unlocked after boot.

`user-presence` uses the same access control as the CA key, and `passcode` drops Touch ID.
With either, every CreateSession signature needs a person, so malware running as you can't get credentials silently, and nothing unattended can use the key.
The prompt names the role, and it appears on the screen of your logged-in, unlocked session, wherever the command started.

In code, every mode uses `[.privateKeyUsage]`, and `user-presence` and `passcode` add `.userPresence` and `.devicePasscode`.
`none` uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, and the other two modes use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

### Credential cache

`credential-process --cache` stores the returned credentials as a generic password in the login keychain.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/credential-cache-dark@2x.png">
  <img alt="On the Mac, the AWS CLI runs credential_process, which starts enclave-ca credential-process --cache. It looks up the login keychain. If the entry is fresh, with more than 10 minutes left, the cached credentials go to the AWS CLI with no prompt. On a miss or a stale entry, the Secure Enclave signs CreateSession with the client key, prompting unless the key's access is none; IAM Roles Anywhere, outside the Mac, receives rolesanywhere:CreateSession and returns temporary AWS credentials; enclave-ca writes the entry to the keychain, reused until 10 minutes before Expiration, and returns the fresh credentials to the AWS CLI." src="img/credential-cache@2x.png" width="1110">
</picture>

- **Key:** service `enclave-ca credential-process`, and an account that is the SHA-256 of every input: the key blob, the certificate, the trust anchor, Roles Anywhere profile, and role ARNs, the duration, and the session name.
- **Lifetime:** reused until 10 minutes before `Expiration`, botocore's mandatory refresh window.
- **Protection:** the login keychain is encrypted with the login password and never synced. Its access list names the binary that wrote the entry, so another program reading it gets a keychain prompt.
- **Failures:** a cache read or write failure is reported on stderr and falls back to a fresh CreateSession.

The cache uses the login keychain because the data-protection keychain, which would allow `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, needs a `keychain-access-groups` entitlement and fails with `-34018` for an ad-hoc signed build.

For the life of a fresh entry, any process running as you can get the same credentials by running `enclave-ca credential-process --cache`.
The cache trades a prompt per command for a prompt per session.
Caching is off by default, because an unattended key gains nothing from it and the cache adds stored secrets.

### CreateSession signing

`credential-process` replaces `aws_signing_helper` on the Mac, which can't use CryptoKit enclave keys.
It builds the [CreateSession](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html) request exactly as the helper's [`signer.go`](https://github.com/aws/rolesanywhere-credential-helper/blob/main/aws_signing_helper/signer.go) does:

- signed headers `content-type;host;x-amz-date;x-amz-x509`
- scope `<date>/<region>/rolesanywhere/aws4_request`, with the region from the trust anchor ARN
- the leaf's serial in decimal as the credential
- a hex DER ECDSA-SHA256 signature over the string to sign

It accepts trust anchor ARNs in the `aws` and `aws-us-gov` partitions, with a region of lowercase letters, digits, and hyphens.
It refuses to run if the certificate's public key doesn't match the key blob.

A test on 2026-11-14 against the live us-west-2 endpoint used a throwaway trust anchor, role, and Roles Anywhere profile.
Credentials came back, the AWS CLI used them through `credential_process` in an empty environment, and a role not on the Roles Anywhere profile got HTTP 403 and exit status 1.

## TPM attestation

`sign --tpm-enrollment --tpm-attestation` refuses to sign unless the host's TPM attests that the CSR's key was generated inside it and can never leave it, and then adds `OU=tpm-ek-pinned` to the leaf.
It proves the key is non-exportable and lives in the TPM whose EK you enrolled.
It does not prove the TPM is genuine hardware, because the EK certificate's chain to the manufacturer isn't checked.
Enrollment requires a secure channel, because the EK certificate it copies off the host is the one thing it takes on trust.
[TPM attestation](tpm-attestation.md) covers the TPM mechanics, every check, and those limits.

## Why not other tools

Checked on 2026-11-14:

| Tool | Problem |
|---|---|
| bash + `openssl` / `security` / `sc_auth` | None can sign an X.509 certificate with a Secure Enclave key. `sc_auth create-ctk-identity` makes an enclave key with a self-signed cert, but you can't set extensions or sign CSRs. |
| `cfssl` | Signs with a key file; no Secure Enclave or PKCS#11. |
| 1Password | No X.509 signing (its agent only produces SSH signatures, and it has no PKCS#11). Using it means exporting the key into `openssl` on every signature. |
| `step` + `step-kms-plugin` (`mackms:`) | `mackms` keeps enclave keys in the data-protection keychain, which needs a `keychain-access-groups` entitlement. The released binaries are ad-hoc signed and fail with `-34018` (`errSecMissingEntitlement`); the README says enclave support is for "signed binaries" only. Its options are no user check at all (`se=true`) or `BiometryCurrentSet` (`bio=true`). The plugin release ships only a checksum file, with no signature or attestation. |

What you have to trust here: Apple's CryptoKit and Security frameworks, Apple's `swift-certificates`/`swift-asn1`/`swift-crypto`, and about 1,400 lines in `Sources/`.
Independent checks: `openssl verify` on every issued cert, and AWS itself on first use.

## Failure modes

| Event | Effect | Response |
|---|---|---|
| Mac erased, restored, replaced, or enclave reset | Key gone; no new signatures. Existing leaves keep working until they expire. | Create a new root and trust anchor, re-sign the existing CSR, delete the old anchor. |
| Mac stolen, locked | Key unusable without unlocking and passing user presence. | Disable the trust anchor anyway. |
| Mac stolen with login password known | Attacker can sign (`.userPresence` accepts the password). | Disable the trust anchor; rotate the root. |
| Malware running as you | Can ask for signatures, each needing your approval; can't extract the key. An unexpected prompt for `enclave-ca` is the warning sign. | Deny, investigate, rotate if in doubt. |
| `ca.key` blob copied off the Mac | Useless without this Mac's enclave. | None needed. |
| Malware running as you, with a prompting client key and `--cache` | Can read fresh cached credentials through `enclave-ca` without a prompt, until they expire. | Keep `--duration-seconds` short; drop `--cache` where a prompt per command is acceptable. |

There is deliberately no backup.
With one root and few leaves, losing the key means a new root and a short recovery, and the remaining validity of existing leaves is the time you have to do it.
Renew leaves early so that time stays long.

## CSR compatibility

tpm2-openssl 1.3.0 writes the CSR's outer signature algorithm as `ecdsa-with-SHA256` followed by an explicit `NULL`, which RFC 5758 §3.2 forbids and swift-certificates rejects.
`parseCSR` drops that one `NULL` and changes nothing else.
That field is outside the signed `certificationRequestInfo`, so the CSR's self-signature is still verified exactly as before.

## Not implemented

CRLs: with one leaf, replacing the root and deleting the old trust anchor revokes everything at once.
Intermediates: the root is `pathlen:0`.
