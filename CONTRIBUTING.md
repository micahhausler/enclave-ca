# Contributing

enclave-ca is one Swift binary and a shell script for the Linux host side.
Bug reports and fixes are welcome.

## What belongs in enclave-ca

enclave-ca signs client-auth certificates for IAM Roles Anywhere with a Secure Enclave key, and acts as a Mac's Roles Anywhere `credential_process`.
Less code to trust is the point, so a feature has to earn its lines.
For anything larger than a bug fix, open an issue first so the design is agreed before you write the code.

## Build and test

Building needs macOS 13 or later and Xcode or the Swift toolchain.
The unit tests use software keys, so they need no Secure Enclave and run in CI on GitHub's macOS runners.

```sh
swift build
swift test
```

### End-to-end test

`scripts/e2e.sh` runs against real IAM Roles Anywhere on a Mac with a Secure Enclave.
It makes a client key and issues its cert, with `openssl` as an independent CA by default or with `enclave-ca` when `E2E_CA=enclave`.
It then creates a throwaway trust anchor, role, and Roles Anywhere profile, gets credentials through the AWS CLI's `credential_process` in an empty environment, checks two refusals, and deletes the AWS resources on exit, pass or fail.

```sh
AWS_PROFILE=admin scripts/e2e.sh                  # openssl as the CA, no prompts
E2E_CA=enclave AWS_PROFILE=admin scripts/e2e.sh   # enclave-ca as the CA, two Touch ID prompts
```

It needs the AWS CLI, OpenSSL 3, `jq`, and credentials that can manage IAM roles and Roles Anywhere.
Run it before a change to signing, `credential-process`, or the CreateSession request merges.

## Layout

- `Sources/enclave-ca/main.swift`: flags, file I/O, and one function per subcommand.
- `Sources/EnclaveCA/`: the library behind each subcommand: enclave keys, issuing, CSR parsing, TPM attestation, CreateSession signing, and the credential cache.
- `Tests/EnclaveCATests/`: unit tests, with public fixtures from a real TPM and `tpm2-openssl`.
- `scripts/tpm-attest.sh`: the Linux host side of TPM enrollment and attestation, using `tpm2-tools`.
- `scripts/e2e.sh`: the end-to-end test.
- `docs/`: the [design and threat model](docs/design.md), [TPM attestation](docs/tpm-attestation.md), and the [Roles Anywhere walkthrough](docs/roles-anywhere.md).

## Conventions

- **Checks and crypto live in `Sources/EnclaveCA/`.** `main.swift` reads flags and files, calls the library, and writes the results.
- **Dependencies stay few and pinned.** `swift-certificates` is pinned exactly in `Package.swift`, and a new dependency needs a written reason in the pull request.
- **Refuse rather than repair.** A CSR, attestation, or certificate that doesn't meet every check is rejected with an error that names the check.
- **Prompts name what is being approved.** A Touch ID prompt says which CN, validity, OU, or role it signs for.
- **Tests stay off the network and out of the keychain.** Unit tests never call AWS, use the Secure Enclave, or touch the real keychain or `$HOME`.

## Keep personal details out of the repo

Never commit an account ID, ARN, credentials, or a key blob.
Test fixtures hold only public data, such as an EK certificate, an AK's public area, a CSR, and an attestation.
Use placeholders such as `HOST`, `REGION`, and `TRUST_ANCHOR_ARN` in docs and examples.
`.gitignore` excludes `*.key`, `*.crt`, and `*.csr` everywhere except the test fixtures.

## Writing docs

- Put one sentence per line in Markdown, so a diff shows the sentence that changed.
- State claims plainly, and date claims about other tools or AWS behavior ("Checked on 2026-11-14").
- The docs in `docs/` describe what is built. Change them in the same pull request as the behavior.

## Pull requests

- Keep each pull request to one change, with its tests.
- Say what changed and why in the description, and link the issue when there is one.
- Make sure `swift test` passes, and say whether you ran `scripts/e2e.sh`.
- Contributions are licensed under Apache 2.0, the project's license.

## Report a bug or a vulnerability

For a bug, open an issue with your enclave-ca version or commit, macOS version, Mac model, the command you ran, and its output.
Redact account IDs and ARNs first.

For a vulnerability, don't open a public issue.
Report it privately through the repository's Security tab.
