# Export classification

This repository (the vault and workflow services) uses only standard, publicly documented
cryptographic algorithms and protocols: AES-256-GCM to envelope-encrypt secrets at rest, with a
key-encryption-key ring derived and wrapped using SHA-256; SSH keypair generation and handling
(Ed25519, RSA-2048/4096, ECDSA P-256), including host-key parsing and SHA-256 fingerprinting, via
golang.org/x/crypto/ssh; X.509 certificate issuance for the Certificate secret type (RSA, ECDSA,
Ed25519, TLS) via go-certkit; and RS256/ES256 JWT verification of Kubernetes projected
ServiceAccount tokens (go-workload-identity) for service-to-service calls. None of it is
non-standard or proprietary cryptography.

This repository's source code is public, so under the US Export Administration Regulations (15
CFR 742.15(b)) it is not subject to the EAR: no classification, licence or notification applies to
it. Builds and binaries produced from this public source carry the same treatment under 15 CFR
734.3(b)(3) and 734.17.

This file is a factual statement about the cryptography used in Sneakers-PAM, not legal advice.
