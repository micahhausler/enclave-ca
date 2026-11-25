# enclave-ca

*A tiny offline certificate authority for IAM Roles Anywhere, with its root key in a Mac's Secure Enclave.*

[IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) gives a machine outside AWS short-lived AWS credentials in exchange for an X.509 certificate, so the machine holds no static access keys.
AWS trusts whatever certificate authority you register as a [trust anchor](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html).
A Roles Anywhere [profile](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html) names the IAM roles a certificate can assume, and each role's trust policy can require a specific certificate subject through [attribute mapping](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/attribute-mapping.html).
The machine signs a [CreateSession](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html) request with its certificate's private key, usually through AWS's [credential helper](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html) as a [`credential_process`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) in an AWS config file profile.

Whoever can sign with the CA's key can mint a certificate for any role that trusts the anchor, which makes that key the one to protect.
[AWS Private CA](https://aws.amazon.com/private-ca/pricing/) can hold that key, and at $400 a month per CA it fits an enterprise fleet rather than a few personal machines.
For a home lab or a handful of machines, `enclave-ca` holds it in the Secure Enclave of the Mac you already have.

- **The key can't leave the Mac.** The Secure Enclave generates it, and it can't be exported or copied to another device.
- **Every signature needs you.** Each one asks for Touch ID or the login password, and one approval never covers a second signature.
- **It signs one kind of thing.** A client-auth leaf for a single name, with every field set by the CA rather than the request.
- **It can check the requester's key.** With TPM attestation, it signs only when a Linux host's TPM proves the key can't leave that TPM.

`enclave-ca` also works on the other side of the exchange.
It can hold a Mac's own Roles Anywhere client key in the Secure Enclave and act as that Mac's `credential_process`, the way a TPM key does on Linux.

## How it fits together

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/overview-dark@2x.png">
  <img alt="The AWS account holds the trust anchor (ca.crt, registered once) and IAM Roles Anywhere, which checks that a leaf chains to the trust anchor and checks the role's trust policy, then returns temporary credentials. Below it, the CA Mac keeps its root key in the Secure Enclave and signs leaves with enclave-ca sign, one Touch ID prompt per signature. Under the CA Mac, a Linux host (server01, key in its TPM) and a Mac client (mac, key in its Secure Enclave) each send a CSR up and get a leaf back. The Mac client sends rolesanywhere:CreateSession, signed by its key, and gets temporary AWS credentials back; the Linux host does the same." src="docs/img/overview@2x.png" width="920">
</picture>

| Where | Key | Made by | Signs |
| --- | --- | --- | --- |
| The CA Mac | Root CA key, prompts on every use | `enclave-ca init` | Leaf certificates, with `enclave-ca sign` |
| A Linux host | TPM client key | `openssl` with `tpm2-openssl` | CreateSession, with `aws_signing_helper` |
| A Mac client | Secure Enclave client key | `enclave-ca client-key` | CreateSession, with `enclave-ca credential-process` |

A Mac client can be the same Mac that holds the CA key.

### What trusts what

AWS issues credentials when a CreateSession request is signed by a certificate's key and that certificate chains to the trust anchor.
The trust anchor holds the root certificate, so AWS trusts every leaf the CA Mac signs.
Each role's trust policy narrows that to one CN through one trust anchor, and can also require `OU=tpm-ek-pinned`.

The CA Mac signs only after you approve a Touch ID prompt that names the CN and validity.
A CSR contributes only its public key and the CN it asks for, which must match the CN you pass; the CA sets every other field.

With TPM attestation, the CA also trusts a Linux host's TPM, pinned once at enrollment from the EK certificate you copy off the host.
After that, `sign` checks the TPM's signed statement that the CSR's key lives in that TPM and can't leave it, and only then marks the leaf `OU=tpm-ek-pinned`.

### What lives where

- **CA Mac:** `ca.key`, the root key wrapped by this Mac's Secure Enclave, useless on any other device. `ca.crt`, the public root. For each attested host, a public enrollment file and attestation.
- **Each client:** its key, wrapped by its TPM or Secure Enclave and useless anywhere else. Its CSR, kept for renewal. Its leaf certificate.
- **AWS:** one trust anchor, plus a role and a Roles Anywhere profile per client.

The CA Mac needs no network access and keeps no inventory.
Each key exists only as the file you pass with `--key`, and nothing records which leaves were issued.
None of the files that move between machines are secret, but some of them need a secure channel, such as SSH with a verified host key.
The EK certificate and AK copied at enrollment decide which TPM the CA trusts, and without attestation, the CSR decides which key gets the leaf.

### How it changes over time

- **Once:** create the root and register it as a trust anchor.
- **Per client:** make a key and CSR on the client, sign it on the CA Mac, create its role and Roles Anywhere profile, and add a profile to its AWS config file.
- **Yearly:** re-sign each client's kept CSR when the expiry notification fires. AWS and the client key stay the same.
- **If the CA Mac dies:** there is no backup of the root key, on purpose. Existing leaves keep working until they expire, which is the time you have to create a new root and trust anchor and re-sign each CSR.

The [walkthrough](docs/roles-anywhere.md) has every command, and the [design doc](docs/design.md) explains the trade-offs and the threat model.

## Requirements

- macOS 13 or later, on an Apple silicon Mac.
- Xcode or the Swift toolchain to build.
- An AWS account with IAM Roles Anywhere, and the AWS CLI to create the trust anchor, role, and Roles Anywhere profile.
- On Linux hosts: a TPM 2.0, `tpm2-tools`, `tpm2-openssl`, and `aws_signing_helper`.

## Install

Homebrew builds `enclave-ca` from the latest release's source:

```sh
brew tap micahhausler/enclave-ca https://github.com/micahhausler/enclave-ca
brew install enclave-ca
```

Each [release](https://github.com/micahhausler/enclave-ca/releases) is a source tarball and its sha256; there are no prebuilt binaries.
From a checkout, `swift build -c release` builds `.build/release/enclave-ca`.

Every build is ad-hoc signed.
`enclave-ca` needs no entitlements and no Developer ID signature, so it works without a $99-a-year [Apple Developer Program](https://developer.apple.com/programs/) membership.

## Client configuration

Each client gets credentials through a `credential_process` line in a profile in its AWS config file, so the AWS CLI and SDKs fetch fresh credentials whenever they need them.
Paths must be absolute, because `credential_process` doesn't expand `~`.

A Linux host uses AWS's `aws_signing_helper` with its TPM key:

```ini
[profile client-profile]
region = us-west-2
credential_process = /home/you/.local/bin/aws_signing_helper credential-process --certificate /home/you/.aws/rolesanywhere/some-host.crt --private-key /home/you/.aws/rolesanywhere/some-host.tss --no-tpm-key-password --trust-anchor-arn TRUST_ANCHOR_ARN --profile-arn PROFILE_ARN --role-arn ROLE_ARN
```

A Mac uses `enclave-ca credential-process`, because `aws_signing_helper` can't use Secure Enclave keys:

```ini
[profile mac]
region = us-west-2
credential_process = /opt/homebrew/bin/enclave-ca credential-process --key /Users/you/.aws/rolesanywhere/mac.key --certificate /Users/you/.aws/rolesanywhere/mac.crt --trust-anchor-arn TRUST_ANCHOR_ARN --profile-arn PROFILE_ARN --role-arn ROLE_ARN --cache
```

A Mac client key needs nothing, Touch ID or the login password, or the login password alone on every use, chosen when the key is made.
For a key that prompts, `--cache` keeps the credentials in the login keychain until shortly before they expire, so it prompts about once per session instead of on every command.

## What gets issued

Root: P-256, ECDSA-SHA256, `CA:TRUE, pathlen:0` (critical), `keyCertSign, cRLSign` (critical), SKI, random 160-bit serial.

Leaf: the CSR's public key with every other field set by the CA (subject `CN=<name>`, or `OU=tpm-ek-pinned, CN=<name>` when TPM-attested):
`CA:FALSE` (critical), `digitalSignature` (critical), `clientAuth`, SKI, AKI, random serial.
Requested extensions in the CSR are ignored.
`sign` refuses a CSR whose self-signature doesn't verify, whose subject isn't exactly `CN=<name>`, or that would outlive the root.

These meet the [Roles Anywhere certificate requirements](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html).

## Docs

- [Design and threat model](docs/design.md): how each key is held, what TPM attestation proves, why this tool rather than `step`, `cfssl`, or 1Password, and what each failure costs.
- [TPM attestation](docs/tpm-attestation.md): how the CA checks that a Linux host's key can't leave its TPM, and what that proves.
- [IAM Roles Anywhere walkthrough](docs/roles-anywhere.md): a Linux host or a Mac from key to credentials, with renewal, recovery, and an emergency stop.
- [Contributing](CONTRIBUTING.md): building, testing, and the end-to-end check against real AWS.

## Dependencies

Apple's [swift-certificates](https://github.com/apple/swift-certificates) (pinned exactly in `Package.swift`), which brings in `swift-asn1` and `swift-crypto`.
Signing goes through CryptoKit's `SecureEnclave.P256`.

## License

enclave-ca is licensed under the [Apache License 2.0](LICENSE).
