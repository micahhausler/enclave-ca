# TPM attestation

TPM attestation lets `enclave-ca sign` check, before the Touch ID prompt, that a CSR's key is a non-exportable key in a Linux host's TPM.
A leaf that passes gets the subject `OU=tpm-ek-pinned, CN=<name>`.
IAM Roles Anywhere [maps](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/attribute-mapping.html) that to the session tag `x509Subject/OU`, so a role's trust policy can refuse any cert issued without the check.

Without attestation, a CSR proves only that its sender holds the private key.
The key could be a file on disk that anyone who reads it can copy.
With attestation, the TPM itself vouches that the key was generated inside it and can never leave.

The [walkthrough](roles-anywhere.md#tpm-attestation-recommended) has the commands.

## TPM building blocks

- **Endorsement key (EK):** the TPM's identity key, derived from the TPM's endorsement seed, so it comes out the same every time it's created. The EK can decrypt but never sign.
- **EK certificate:** the manufacturer's certificate for the EK's public key, stored in the TPM's non-volatile memory. The ECC one is at NV index `0x1c0000a`.
- **Attestation key (AK):** a signing key created inside the TPM with the EK as its parent. It is *restricted*: the TPM signs with it only data the TPM produced itself.
- **`TPM_GENERATED_VALUE`:** a magic number at the start of every statement the TPM produces. The TPM refuses to sign external data with a restricted key if that data starts with this value, so nothing outside the TPM can forge a statement.
- **Name:** the hash of an object's public area, which includes its public key and its attributes. A name commits to one exact key with one exact set of attributes.
- **Key attributes:** flags fixed when a key is created.
  - `fixedTPM`: the key can never be copied out of this TPM.
  - `fixedParent`: the key can never move under a different parent.
  - `sensitiveDataOrigin`: the TPM generated the private key itself, rather than importing it.
  - `restricted`, `sign`, `decrypt`: what the key may be used for.
- **MakeCredential and ActivateCredential:** a challenge anyone can create in software with the EK's public key and a name. The challenge wraps a secret so that only the TPM holding that EK can unwrap it, and only while an object with exactly that name is loaded in it.
- **Certify:** the AK signs a statement that names another key loaded in the same TPM.

The TCG [TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/) specification defines all of these.
The tpm2-tools man pages for [`tpm2_createak`](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_createak.1/), [`tpm2_makecredential`](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_makecredential.1/), [`tpm2_activatecredential`](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_activatecredential.1/), and [`tpm2_certify`](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_certify.1/) show the host-side commands.

## Chain of evidence

Each step extends trust from something already trusted to one more key:

1. **The EK certificate you copy off the host pins the EK.** It is the one thing enrollment takes on trust, so it has to reach the CA over a secure channel.
2. **Credential activation proves the AK lives in that EK's TPM.** Only that TPM, with that AK loaded, can answer the challenge.
3. **The AK's attributes prove it can't be faked, given a genuine EK.** A TPM refuses to import a key with `fixedTPM` or `restricted` set, so a key with both that passes activation was created inside the TPM. Attributes are just bytes in a public area, so with a software EK they prove nothing.
4. **Certify proves the client key lives in the same TPM.** The AK signs the client key's name, and the name commits to the key's attributes, including `fixedTPM`.
5. **The CSR's public key must match the certified key.** That ties the attestation to the CSR being signed.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/attestation-dark@2x.png">
  <img alt="Sequence diagram between server01's TPM, tpm-attest.sh on server01, and enclave-ca on the CA Mac. Enrollment, once per TPM: tpm-attest.sh keys creates the AK under the EK and gets ak.pub, ak.priv, and ek.crt; ek.crt and ak.pub go to the CA Mac over a secure channel; enclave-ca tpm-challenge checks the AK's attributes and runs MakeCredential, writing a pending server01.tpm.json; server01.challenge goes back; tpm-attest.sh activate runs ActivateCredential, which recovers the secret only if this TPM holds that EK and AK; server01.activated carries the secret back; enclave-ca tpm-enroll checks its hash and completes the enrollment. Issuance, once per client key: tpm-attest.sh certify has the TPM certify the client key with the AK, returning TPMS_ATTEST and the AK signature; server01.attest.pem and the CSR go to the CA Mac; enclave-ca sign checks the enrollment, the AK signature, TPM_GENERATED_VALUE and the certify type, the name, the key attributes, and that the key is the CSR's, then asks for Touch ID; server01.crt comes back with OU=tpm-ek-pinned, CN=server01." src="img/attestation@2x.png" width="1000">
</picture>

## Enrollment (once per TPM)

Enrollment pins a host's TPM to a CN.
It requires a secure channel between the host and the CA, such as SSH with a verified host key.
Anyone who can replace `ek.crt` and `ak.pub` in transit can enroll a software EK and AK, answer the challenge, and then forge attestations that pass every check in `sign`.

1. **Host, `tpm-attest.sh keys`:** creates the AK under the ECC EK, reads the EK certificate from NV, and checks the certificate is for the EK this TPM derives. It sends `ek.crt` and `ak.pub` to the CA; `ak.priv`, wrapped by the TPM, stays on the host.
2. **CA, `enclave-ca tpm-challenge`:** checks that the AK is a restricted ECDSA P-256 signing key with SHA-256, generated in the TPM (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `restricted`, `sign`, not `decrypt`). It then runs MakeCredential in software: a random secret wrapped to the EK and bound to the AK's name. It writes the pending enrollment, with the secret's SHA-256, and the challenge.
3. **Host, `tpm-attest.sh activate`:** loads the AK and runs ActivateCredential, which recovers the secret only if this TPM holds that EK and that AK.
4. **CA, `enclave-ca tpm-enroll`:** compares the recovered secret's hash with the pending one and marks the enrollment complete.

The enrollment file holds the CN, the EK certificate, and the AK's public area.
It holds no secrets.

## Issuance (once per client key)

1. **Host, `tpm-attest.sh certify`:** loads the AK and the client key and runs Certify over the client key. It bundles the client key's public area, the signed statement (`TPMS_ATTEST`), and the AK's signature into one PEM file.
2. **CA, `enclave-ca sign --tpm-enrollment --tpm-attestation`:** checks, before the Touch ID prompt, that:
   - the enrollment is complete and is for the CN being signed
   - the AK's signature over the statement verifies
   - the statement starts with `TPM_GENERATED_VALUE` and is of type certify
   - the certified name is the hash of the supplied public area
   - the public area has `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, and `sign`
   - the public area's key is the CSR's public key

If every check passes, the leaf gets `OU=tpm-ek-pinned`.
If any fails, `sign` refuses and names the check.

The attestation carries no nonce, because `tpm2_certify` 5.7 can't set qualifying data.
None is needed: a `fixedTPM` key can never leave the TPM, so an old attestation of the same key is still true.
Keep the attestation file with the CSR and reuse it at renewal.

## What `tpm-ek-pinned` proves

`tpm-ek-pinned` proves the key is non-exportable and lives in the TPM whose EK you enrolled.

It does not prove the TPM is genuine hardware.
`enclave-ca` doesn't check the EK certificate's chain to the manufacturer, so enrollment trusts that the EK certificate you copied came from the host, over a secure channel.
Intel PTT EK certificates also aren't valid DER (they encode `critical FALSE` and `cA FALSE` explicitly), so `enclave-ca` reads only their public key, with a generic DER walk.

Someone who can write the enrollment file as you could pin their own AK.
They would still need your Touch ID for each signature, and the prompt names the OU being signed.

Clearing a TPM destroys the keys under its storage hierarchy, including the client key, so a cleared TPM needs a new client key and a new attestation.

## Future work

- **Pin the EK by fingerprint.** `tpm-attest.sh keys` and `enclave-ca tpm-challenge` would both print the SHA-256 of the EK's public key, so you can compare them over a channel other than the one carrying the files, such as the host's console. `sign` would also print the CSR key's fingerprint, ideally in the Touch ID prompt, so a CSR swapped in transit is visible without attestation.
- **Sign the enrollment record.** `tpm-enroll` would ask for Touch ID, naming the CN and the EK fingerprint, and sign the enrollment file with a Secure Enclave key. `sign` would refuse an enrollment whose signature doesn't verify, so changing the file at rest would need your approval.
