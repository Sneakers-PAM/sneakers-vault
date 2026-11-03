-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- The SHA-256 fingerprints of the TLS certificates the connector accepts for
-- a target (Target.tls_cert_pins), 64 lowercase hex digits each, in order.
-- Public, not secrets. Replaced as a whole on every state snapshot, like
-- target_ssh_host_keys, so there is no foreign key to targets.
CREATE TABLE public.target_tls_cert_pins (
    target_id text NOT NULL,
    ordinal integer NOT NULL,
    fingerprint text NOT NULL,
    CONSTRAINT target_tls_cert_pins_pkey PRIMARY KEY (target_id, ordinal)
);

CREATE INDEX target_tls_cert_pins_fingerprint_idx ON public.target_tls_cert_pins USING btree (fingerprint);
