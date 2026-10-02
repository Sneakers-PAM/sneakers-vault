-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- SSH host key pins per target: the public keys the SSH broker accepts for
-- the target, in saved order, each with its SHA256 fingerprint. Public keys,
-- not secrets. Replaced as a whole on every state snapshot, like
-- target_raci_rules, so there is no foreign key to targets.
CREATE TABLE public.target_ssh_host_keys (
    target_id text NOT NULL,
    ordinal integer NOT NULL,
    public_key text NOT NULL,
    fingerprint text NOT NULL,
    CONSTRAINT target_ssh_host_keys_pkey PRIMARY KEY (target_id, ordinal)
);

CREATE INDEX target_ssh_host_keys_fingerprint_idx ON public.target_ssh_host_keys USING btree (fingerprint);
