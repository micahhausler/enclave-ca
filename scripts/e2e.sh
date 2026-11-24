#!/usr/bin/env bash
# End-to-end test against real IAM Roles Anywhere.
#
# Needs a Mac with a Secure Enclave, the AWS CLI, OpenSSL 3, and jq,
# and AWS credentials allowed to manage IAM roles and Roles Anywhere.
#
#   AWS_PROFILE=admin scripts/e2e.sh            # openssl CA, no prompts
#   E2E_CA=enclave AWS_PROFILE=admin scripts/e2e.sh   # enclave-ca CA, two Touch ID prompts
#
# It creates a trust anchor, profile, and role named enclave-ca-e2e-<random>
# and deletes them on exit, pass or fail.

set -euo pipefail

E2E_CA=${E2E_CA:-openssl}
REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}
NAME="enclave-ca-e2e-$(openssl rand -hex 4)"
CN="$NAME"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
BIN="$WORK/enclave-ca"

TA_ID=""
PROFILE_ID=""
ROLE_CREATED=""

log() { printf '==> %s\n' "$*" >&2; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
aws_() { aws --region "$REGION" --output json "$@"; }

cleanup() {
    local rc=$?
    set +e
    log "cleanup"
    [[ -n $PROFILE_ID ]] && aws_ rolesanywhere delete-profile --profile-id "$PROFILE_ID" >/dev/null && echo "deleted profile $PROFILE_ID" >&2
    [[ -n $TA_ID ]] && aws_ rolesanywhere delete-trust-anchor --trust-anchor-id "$TA_ID" >/dev/null && echo "deleted trust anchor $TA_ID" >&2
    [[ -n $ROLE_CREATED ]] && aws_ iam delete-role --role-name "$NAME" && echo "deleted role $NAME" >&2
    rm -rf "$WORK"
    if [[ $rc -eq 0 ]]; then echo "PASS" >&2; else echo "FAIL (exit $rc)" >&2; fi
    exit $rc
}
trap cleanup EXIT

for tool in aws jq; do command -v "$tool" >/dev/null || fail "$tool not found"; done
openssl version | grep -q '^OpenSSL 3' || fail "need OpenSSL 3 (got: $(openssl version))"

log "build"
(cd "$ROOT" && swift build -c release >&2)
cp "$ROOT/.build/release/enclave-ca" "$BIN"

ACCOUNT=$(aws_ sts get-caller-identity --query Account --output text)
log "account $ACCOUNT, region $REGION, name $NAME, CA $E2E_CA"

cd "$WORK"

log "client-key"
"$BIN" client-key --key client.key --csr client.csr --cn "$CN" >&2
[[ $(stat -f %Lp client.key) == 600 ]] || fail "client.key mode is not 0600"
openssl req -in client.csr -noout -verify 2>&1 | grep -q 'verify OK' || fail "CSR self-signature does not verify in openssl"
[[ $(openssl req -in client.csr -noout -subject) == "subject=CN=$CN" ]] || fail "CSR subject is wrong"
if "$BIN" client-key --key client.key --csr other.csr --cn "$CN" 2>/dev/null; then fail "client-key overwrote an existing key"; fi

log "issue leaf ($E2E_CA CA)"
case $E2E_CA in
openssl)
    openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout ca.pem -out ca.crt -days 2 -subj "/CN=$NAME CA" \
        -addext basicConstraints=critical,CA:TRUE,pathlen:0 \
        -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
    printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature \
        extendedKeyUsage=clientAuth subjectKeyIdentifier=hash authorityKeyIdentifier=keyid >leaf.ext
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.pem -days 1 -sha256 \
        -extfile leaf.ext -out client.crt 2>/dev/null
    ;;
enclave)
    "$BIN" init --key ca.key --cert ca.crt --cn "$NAME CA" --days 2 >&2
    "$BIN" sign --key ca.key --ca-cert ca.crt --csr client.csr --cn "$CN" --days 1 --out client.crt >&2
    ;;
*) fail "E2E_CA must be openssl or enclave" ;;
esac
openssl verify -CAfile ca.crt -purpose sslclient client.crt >&2

log "create AWS resources"
jq -n --arg name "$NAME" --rawfile pem ca.crt '{
    name: $name, enabled: true,
    source: {sourceType: "CERTIFICATE_BUNDLE", sourceData: {x509CertificateData: $pem}}
}' >ta.json
TA_ARN=$(aws_ rolesanywhere create-trust-anchor --cli-input-json file://ta.json --query trustAnchor.trustAnchorArn --output text)
TA_ID=${TA_ARN##*/}

jq -n --arg ta "$TA_ARN" --arg cn "$CN" '{
    Version: "2012-10-17",
    Statement: [{
        Effect: "Allow",
        Principal: {Service: "rolesanywhere.amazonaws.com"},
        Action: ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
        Condition: {
            ArnEquals: {"aws:SourceArn": $ta},
            StringEquals: {"aws:PrincipalTag/x509Subject/CN": $cn}
        }
    }]
}' >trust.json
ROLE_ARN=$(aws_ iam create-role --role-name "$NAME" --assume-role-policy-document file://trust.json \
    --description "enclave-ca e2e test, safe to delete" --query Role.Arn --output text)
ROLE_CREATED=1

PROFILE_ARN=$(aws_ rolesanywhere create-profile --name "$NAME" --role-arns "$ROLE_ARN" --enabled \
    --query profile.profileArn --output text)
PROFILE_ID=${PROFILE_ARN##*/}

cp_args=(credential-process --key "$WORK/client.key" --certificate "$WORK/client.crt"
    --trust-anchor-arn "$TA_ARN" --profile-arn "$PROFILE_ARN")

log "credential-process (retrying while IAM propagates)"
ok=""
for i in $(seq 1 12); do
    if "$BIN" "${cp_args[@]}" --role-arn "$ROLE_ARN" >creds.json 2>err.txt; then ok=1; break; fi
    echo "attempt $i: $(cat err.txt)" >&2
    sleep 5
done
[[ -n $ok ]] || fail "credential-process never succeeded"
jq -e '.Version == 1 and (.AccessKeyId | startswith("ASIA")) and (.SecretAccessKey | length > 0)
    and (.SessionToken | length > 0) and (.Expiration | length > 0)' creds.json >/dev/null \
    || fail "credential-process output is not valid process-credentials JSON"

log "AWS CLI through credential_process, empty environment"
cat >config <<EOF
[profile e2e]
region = $REGION
credential_process = $BIN ${cp_args[*]} --role-arn $ROLE_ARN
EOF
ARN=$(env -i HOME="$WORK" PATH="$PATH" AWS_CONFIG_FILE="$WORK/config" AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    aws --profile e2e sts get-caller-identity --query Arn --output text)
# Roles Anywhere names the session after the leaf's serial in lowercase hex.
SERIAL=$(openssl x509 -in client.crt -noout -serial | cut -d= -f2 | tr A-F a-f)
want="arn:aws:sts::$ACCOUNT:assumed-role/$NAME/$SERIAL"
[[ $ARN == "$want" ]] || fail "caller is $ARN, want $want"
echo "$ARN" >&2

log "negative: role not on the profile"
if "$BIN" "${cp_args[@]}" --role-arn "arn:aws:iam::$ACCOUNT:role/$NAME-not-on-profile" >/dev/null 2>err.txt; then
    fail "credential-process succeeded for a role not on the profile"
fi
grep -q 403 err.txt || fail "expected HTTP 403, got: $(cat err.txt)"

log "negative: certificate for a different key"
"$BIN" client-key --key other.key --csr other.csr --cn "$CN" >/dev/null
rc=0
"$BIN" "${cp_args[@]/client.key/other.key}" --role-arn "$ROLE_ARN" >/dev/null 2>err.txt || rc=$?
[[ $rc == 2 ]] && grep -q 'is not for the key' err.txt || fail "key/cert mismatch not refused (rc=$rc): $(cat err.txt)"
