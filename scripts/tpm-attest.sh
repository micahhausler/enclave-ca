#!/usr/bin/env bash
# Host side of TPM attestation for enclave-ca, using tpm2-tools (tested with 5.7).
#
#   tpm-attest.sh keys DIR
#       Create an attestation key (AK) under the ECC endorsement key and write, into DIR:
#       ak.pub / ak.priv (TPM-wrapped AK, stays on the host), and for the CA:
#       ek.crt (ECC EK certificate from NV 0x1c0000a, DER) and ak.pub.
#   tpm-attest.sh activate DIR CHALLENGE OUT
#       Recover the secret in the CA's challenge (from `enclave-ca tpm-challenge`) into OUT.
#   tpm-attest.sh certify DIR KEY.tss OUT.pem
#       Have the AK certify the client key KEY.tss (a tpm2-openssl TSS2 PEM key) and write the
#       attestation bundle that `enclave-ca sign --tpm-attestation` reads.
#
# Nothing is persisted in the TPM: the EK is re-derived from the endorsement seed each time and the
# AK is reloaded from DIR. Expects the kernel resource manager (/dev/tpmrm0), which flushes
# transient objects when each command exits.

set -euo pipefail

EK_CERT_NV=0x1c0000a

die() { echo "tpm-attest: $*" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

load_ek() { tpm2_createek -G ecc -c "$WORK/ek.ctx" >/dev/null; }

# The EK's auth is a policy on the endorsement hierarchy, so using it as a parent needs a policy session.
ek_session() {
    tpm2_startauthsession --policy-session -S "$WORK/s.ctx" >/dev/null
    tpm2_policysecret -S "$WORK/s.ctx" -c e >/dev/null
}

load_ak() {
    local dir=$1
    load_ek
    ek_session
    tpm2_load -C "$WORK/ek.ctx" -P "session:$WORK/s.ctx" -u "$dir/ak.pub" -r "$dir/ak.priv" -c "$WORK/ak.ctx" >/dev/null
    tpm2_flushcontext "$WORK/s.ctx"
}

cmd=${1:-}
case $cmd in
keys)
    [[ $# == 2 ]] || die "usage: keys DIR"
    dir=$2
    for f in ak.pub ak.priv ek.crt; do [[ ! -e $dir/$f ]] || die "$dir/$f already exists"; done
    load_ek
    tpm2_createak -C "$WORK/ek.ctx" -c "$WORK/ak.ctx" -G ecc -g sha256 -s ecdsa \
        -u "$WORK/ak.pub" -r "$WORK/ak.priv" >/dev/null
    chmod 600 "$WORK/ak.priv"
    tpm2_nvread "$EK_CERT_NV" -o "$WORK/ek.crt"
    # The EK certificate must be for the EK this TPM derives, or the CA's challenge can't be answered.
    tpm2_readpublic -c "$WORK/ek.ctx" -f pem -o "$WORK/ek.pem" >/dev/null
    openssl x509 -inform DER -in "$WORK/ek.crt" -noout -pubkey | cmp -s - "$WORK/ek.pem" \
        || die "EK certificate at NV $EK_CERT_NV does not match the ECC EK"
    for f in ak.pub ak.priv ek.crt; do mv "$WORK/$f" "$dir/$f"; done
    echo "wrote $dir/ak.pub $dir/ak.priv $dir/ek.crt; copy ek.crt and ak.pub to the CA"
    ;;
activate)
    [[ $# == 4 ]] || die "usage: activate DIR CHALLENGE OUT"
    dir=$2 challenge=$3 out=$4
    load_ak "$dir"
    ek_session
    tpm2_activatecredential -c "$WORK/ak.ctx" -C "$WORK/ek.ctx" -i "$challenge" -o "$out" \
        -P "session:$WORK/s.ctx" >/dev/null
    tpm2_flushcontext "$WORK/s.ctx"
    echo "wrote $out; copy it to the CA for enclave-ca tpm-enroll"
    ;;
certify)
    [[ $# == 4 ]] || die "usage: certify DIR KEY.tss OUT.pem"
    dir=$2 key=$3 out=$4
    load_ak "$dir"
    tpm2_load -r "$key" -c "$WORK/key.ctx" >/dev/null || die "could not load $key"
    tpm2_readpublic -c "$WORK/key.ctx" -o "$WORK/key.pub" >/dev/null
    tpm2_certify -c "$WORK/key.ctx" -C "$WORK/ak.ctx" -g sha256 \
        -o "$WORK/attest" -s "$WORK/sig" -f plain >/dev/null
    {
        for pair in "TPM2B PUBLIC:key.pub" "TPMS ATTEST:attest" "TPM ECDSA SIGNATURE:sig"; do
            label=${pair%%:*} file=${pair#*:}
            echo "-----BEGIN $label-----"
            base64 -w 64 "$WORK/$file"
            echo "-----END $label-----"
        done
    } >"$out"
    echo "wrote $out"
    ;;
*) die "usage: tpm-attest.sh keys|activate|certify ..." ;;
esac
