# Export classification

Sneakers-PAM uses only standard, publicly documented cryptographic algorithms and protocols: TLS
1.2/1.3; SSH and SSH certificates (Ed25519, RSA, ECDSA); AES-256-GCM and AES-XTS; TPM 2.0 sealing;
age (X25519, ChaCha20-Poly1305, HKDF, scrypt); Ed25519, ECDSA and RSA signatures; Argon2id, HKDF,
HMAC and SHA-256; and TOTP (RFC 6238). None of it is non-standard or proprietary cryptography.

This repository's source code is public, so under the US Export Administration Regulations (15
CFR 742.15(b)) it is not subject to the EAR: no classification, licence or notification applies to
it. Builds and binaries produced from this public source carry the same treatment under 15 CFR
734.3(b)(3) and 734.17.

This file is a factual statement about the cryptography used in Sneakers-PAM, not legal advice.
