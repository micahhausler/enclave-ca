# IAM Roles Anywhere with enclave-ca

This walkthrough gives a Linux host or a Mac short-lived AWS credentials from a non-exportable key, with no static access keys.
The CA is `enclave-ca` on a Mac.
A Linux host keeps its key in its TPM and gets credentials through `aws_signing_helper`.
A Mac keeps its key in its Secure Enclave and gets credentials through `enclave-ca credential-process`.
The steps follow AWS's [getting started](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html) guide, with `enclave-ca` as the trust anchor's CA.

The commands use shell variables.
Set these in each shell you run them in, on the CA Mac and on the client:

```sh
export CLIENT=some-host
export PROFILE_NAME=client-profile
```

`CLIENT` is the Linux host or Mac getting credentials, and its certificate's CN; Linux examples also reach it with `ssh`.
`PROFILE_NAME` is the AWS config file profile to create on the client.

Steps 1 and 3 set `TRUST_ANCHOR_ARN`, `ROLE_ARN`, `PROFILE_ARN`, and `PROFILE_ID` from command output.
Copy `TRUST_ANCHOR_ARN`, `PROFILE_ARN`, and `ROLE_ARN` to the client's shell for step 4.

## 1. Root CA and trust anchor (one time, on the CA Mac)

```sh
enclave-ca init \
  --key ca.key \
  --cert ca.crt \
  --cn "Home Root CA"

export AWS_PROFILE=admin-profile AWS_REGION=us-west-2

TRUST_ANCHOR_ARN=$(aws rolesanywhere create-trust-anchor \
  --name home-root \
  --enabled \
  --source "$(jq -n --rawfile c ca.crt '{sourceType:"CERTIFICATE_BUNDLE",sourceData:{x509CertificateData:$c}}')" \
  --query trustAnchor.trustAnchorArn \
  --output text)
```

`init` asks for Touch ID once and refuses to overwrite either file.
`ca.key` (mode 0600) works only on this Mac, so it isn't a secret in the usual sense, but don't publish it either.
`ca.crt` is public.

Roles Anywhere sends expiry [notifications](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/customize-notification-settings.html) by default, 45 days before the root or any leaf expires, to AWS Health and EventBridge.
AWS User Notifications can route them to email.

## 2. Client key and certificate

### Linux host

Install the tools on the host, with `apt`:

```sh
sudo apt install tpm2-tools tpm2-openssl
```

Or with `dnf`:

```sh
sudo dnf install tpm2-tools tpm2-openssl
```

Then join the `tss` group and check that OpenSSL finds the TPM provider:

```sh
sudo usermod -aG tss "$USER"   # then log in again
openssl list -providers -provider tpm2   # should list tpm2
```

Install `aws_signing_helper` from the [credential helper](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html) page (the Linux binary for your architecture), check its SHA-256 against the page, and put it in `~/.local/bin`.

Make the TPM key and CSR on the host:

```sh
mkdir -p ~/.aws/rolesanywhere && cd ~/.aws/rolesanywhere
openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -out "$CLIENT.tss"
head -1 "$CLIENT.tss"   # -----BEGIN TSS2 PRIVATE KEY-----
openssl req -provider tpm2 -provider default -new -key "$CLIENT.tss" -subj "/CN=$CLIENT" -out "$CLIENT.csr"
```

`$CLIENT.tss` is wrapped by this host's TPM and is useless anywhere else.
Keep `$CLIENT.csr`, because renewal re-signs it.

#### TPM attestation (recommended)

Attestation lets the CA check, before signing, that the CSR's key is a non-exportable key in this host's TPM, and mark the cert `OU=tpm-ek-pinned` so the role can require it.
[TPM attestation](tpm-attestation.md) explains how it works and what it does and doesn't prove.
It needs the ECC EK certificate at NV index `0x1c0000a` (Intel PTT and most discrete TPMs ship one).

Enroll once, over a secure channel such as SSH with a verified host key.
The EK certificate copied here decides which TPM the CA trusts, so a swapped `ek.crt` and `ak.pub` would let someone else's key pass attestation.
On the host, with [`scripts/tpm-attest.sh`](../scripts/tpm-attest.sh) copied to `~/.local/bin`:

```sh
tpm-attest.sh keys ~/.aws/rolesanywhere   # AK under the EK; writes ak.pub, ak.priv, ek.crt
```

On the CA Mac:

```sh
scp "$CLIENT":.aws/rolesanywhere/{ek.crt,ak.pub} .
enclave-ca tpm-challenge \
  --cn "$CLIENT" \
  --ek-cert ek.crt \
  --ak-public ak.pub \
  --enrollment "$CLIENT.tpm.json" \
  --out "$CLIENT.challenge"
scp "$CLIENT.challenge" "$CLIENT:.aws/rolesanywhere/"
ssh "$CLIENT" tpm-attest.sh activate .aws/rolesanywhere ".aws/rolesanywhere/$CLIENT.challenge" ".aws/rolesanywhere/$CLIENT.activated"
scp "$CLIENT:.aws/rolesanywhere/$CLIENT.activated" .
enclave-ca tpm-enroll \
  --enrollment "$CLIENT.tpm.json" \
  --activated "$CLIENT.activated"
```

Only the TPM holding that EK, with that AK loaded, can answer the challenge.
`$CLIENT.tpm.json` is the pinned EK certificate and AK; it holds no secrets.

Then attest the client key (once per key):

```sh
ssh "$CLIENT" tpm-attest.sh certify .aws/rolesanywhere ".aws/rolesanywhere/$CLIENT.tss" ".aws/rolesanywhere/$CLIENT.attest.pem"
scp "$CLIENT:.aws/rolesanywhere/$CLIENT.attest.pem" .
```

Keep `$CLIENT.attest.pem` with `$CLIENT.csr`; it stays valid as long as the key and the enrollment do.

#### Sign the host's certificate

On the CA Mac:

```sh
scp "$CLIENT:.aws/rolesanywhere/$CLIENT.csr" .
# Omit --tpm-enrollment and --tpm-attestation without attestation.
enclave-ca sign \
  --key ca.key \
  --ca-cert ca.crt \
  --csr "$CLIENT.csr" \
  --cn "$CLIENT" \
  --out "$CLIENT.crt" \
  --tpm-enrollment "$CLIENT.tpm.json" \
  --tpm-attestation "$CLIENT.attest.pem"
openssl verify -CAfile ca.crt -purpose sslclient "$CLIENT.crt"
scp "$CLIENT.crt" "$CLIENT:.aws/rolesanywhere/"
```

`sign` asks for Touch ID once per leaf and writes atomically, so a failed run never leaves a truncated cert behind.
With attestation, `sign` checks it before the Touch ID prompt and refuses if it fails; the leaf's subject is `OU=tpm-ek-pinned, CN=$CLIENT`.

### Mac

On the client Mac, which can be the same Mac that holds the CA key:

```sh
mkdir -p ~/.aws/rolesanywhere && cd ~/.aws/rolesanywhere
enclave-ca client-key \
  --key "$CLIENT.key" \
  --csr "$CLIENT.csr" \
  --cn "$CLIENT" \
  --access user-presence
```

`--access` sets what every use of the key needs:

- `none` (the default): nothing, like a password-less TPM key. Unattended jobs can use it, and so can any process running as you.
- `user-presence`: Touch ID or the login password is required for every uncached invocation.
- `passcode`: the login password is required for every uncached invocation.

With `user-presence` or `passcode`, `client-key` prompts once to sign the CSR.
The [design doc](design.md#access-modes) has the Secure Enclave access control behind each mode.

Sign the CSR on the CA Mac as for a Linux host, without the attestation flags, and copy `$CLIENT.crt` back next to `$CLIENT.key`.
Keep `$CLIENT.csr`, because renewal re-signs it.

## 3. Role and Roles Anywhere profile (per client, on the CA Mac)

The role's trust policy allows only this CN, only through this trust anchor, and, for an attested Linux host, only a TPM-attested key.
Roles Anywhere maps the certificate's subject to the `x509Subject/*` session tags, as described in [attribute mapping](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/attribute-mapping.html).
Drop the `x509Subject/OU` line for a Mac or a host without attestation.
`perms.json` is the role's permissions policy, with whatever the client needs.

```sh
cat > trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "rolesanywhere.amazonaws.com"},
    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
    "Condition": {
      "StringEquals": {
        "aws:PrincipalTag/x509Subject/CN": "$CLIENT",
        "aws:PrincipalTag/x509Subject/OU": "tpm-ek-pinned"
      },
      "ArnEquals": {"aws:SourceArn": "$TRUST_ANCHOR_ARN"}
    }
  }]
}
EOF

ROLE_ARN=$(aws iam create-role \
  --role-name "$CLIENT" \
  --assume-role-policy-document file://trust.json \
  --query Role.Arn \
  --output text)

aws iam put-role-policy \
  --role-name "$CLIENT" \
  --policy-name "$CLIENT" \
  --policy-document file://perms.json

read -r PROFILE_ID PROFILE_ARN < <(aws rolesanywhere create-profile \
  --name "$CLIENT" \
  --enabled \
  --role-arns "$ROLE_ARN" \
  --duration-seconds 3600 \
  --query '[profile.profileId, profile.profileArn]' \
  --output text)
```

## 4. Client AWS config

`credential_process` is the AWS CLI's [external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) setting, which the AWS SDKs also read.
It needs absolute paths, because it doesn't expand `~`, so these commands write `$HOME` out in full.

### Linux host

```sh
cat >> ~/.aws/config <<EOF

[profile $PROFILE_NAME]
region = us-west-2
credential_process = $HOME/.local/bin/aws_signing_helper credential-process --certificate $HOME/.aws/rolesanywhere/$CLIENT.crt --private-key $HOME/.aws/rolesanywhere/$CLIENT.tss --no-tpm-key-password --trust-anchor-arn $TRUST_ANCHOR_ARN --profile-arn $PROFILE_ARN --role-arn $ROLE_ARN
EOF
```

`--no-tpm-key-password` is needed because the TPM key has no password, and the helper expects one by default.

### Mac

```sh
cat >> ~/.aws/config <<EOF

[profile $PROFILE_NAME]
region = us-west-2
credential_process = /opt/homebrew/bin/enclave-ca credential-process --key $HOME/.aws/rolesanywhere/$CLIENT.key --certificate $HOME/.aws/rolesanywhere/$CLIENT.crt --trust-anchor-arn $TRUST_ANCHOR_ARN --profile-arn $PROFILE_ARN --role-arn $ROLE_ARN --cache
EOF
```

`enclave-ca credential-process` replaces `aws_signing_helper`, which can't use Secure Enclave keys.
It signs the CreateSession request with the [Roles Anywhere signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html), matching [`aws_signing_helper`](https://github.com/aws/rolesanywhere-credential-helper), and prints the standard process-credentials JSON.
It prompts on every call unless the key's access is `none`.

The AWS CLI runs `credential_process` on every command, so a prompting key without `--cache` prompts every time.
`--cache` keeps the credentials in the login keychain and reuses them until 10 minutes before they expire, so the prompt comes about once per session duration.
Each combination of key, certificate, trust anchor, Roles Anywhere profile, role, duration, and session name gets its own entry.
While an entry is fresh, any process running as you can get those credentials through `enclave-ca` without a prompt.
A rebuilt binary gets one keychain prompt for an existing entry, because the entry's access list names the binary that wrote it.
Leave `--cache` off for a `none` key, which gains nothing from it.

### Check it

```sh
aws sts get-caller-identity --profile "$PROFILE_NAME"
```

A daily local check that fails 30 days before expiry:

```sh
openssl x509 -in ~/.aws/rolesanywhere/"$CLIENT.crt" -noout -checkend $((30*86400))
```

## Renewal (yearly)

Renew when the 45-day alert fires.
The remaining validity of the current leaf is your margin if the CA Mac dies.

Re-sign the kept CSR and copy the cert back; for a Linux host:

```sh
enclave-ca sign \
  --key ca.key \
  --ca-cert ca.crt \
  --csr "$CLIENT.csr" \
  --cn "$CLIENT" \
  --out "$CLIENT.crt" \
  --tpm-enrollment "$CLIENT.tpm.json" \
  --tpm-attestation "$CLIENT.attest.pem"
openssl verify -CAfile ca.crt -purpose sslclient "$CLIENT.crt"
scp "$CLIENT.crt" "$CLIENT:.aws/rolesanywhere/"
ssh "$CLIENT" aws sts get-caller-identity --profile "$PROFILE_NAME"
```

Renewal needs no AWS changes and no new client key.
Make a new client key only if a Linux host's TPM is cleared, a Mac is erased, or you suspect the client is compromised.
Clearing a TPM resets its storage hierarchy but not its endorsement seed, so the EK and the enrollment survive; certify the new client key before signing it.

## Recovery (CA key lost, or root rotation, or revoking a leaf)

Existing leaves keep working until they expire; only new signatures are blocked.

1. `enclave-ca init` on the (new) CA Mac.
2. Create a new trust anchor.
3. Point each role's `aws:SourceArn` at the new trust anchor.
4. Re-sign each client's CSR and copy the cert to the client.
5. Update `--trust-anchor-arn` in each client's `~/.aws/config` and run `get-caller-identity`.
6. Delete the old trust anchor.

Step 6 also revokes every cert the old root issued.

## Emergency stop (client stolen or compromised)

1. `aws rolesanywhere disable-profile --profile-id "$PROFILE_ID"`, or
2. add a `Deny` on `aws:PrincipalTag/x509Subject/CN` = `$CLIENT` to the role trust policy.

Then make a new client key and run the recovery steps so the old cert no longer chains to a trusted anchor.
