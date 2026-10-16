-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- A pending daily rollup of routine (unchanged-result) machine heartbeat
-- checks for one secret, folded into a single audit record instead of one
-- per check. Flushed (emitted, then cleared) at the first state change or
-- when the day closes, whichever comes first. One row per secret: a secret
-- with no pending rollup has none.
CREATE TABLE public.heartbeat_audit_summary (
    secret_id text NOT NULL,
    day date NOT NULL,
    started_at timestamp with time zone NOT NULL,
    last_at timestamp with time zone NOT NULL,
    checks integer DEFAULT 0 NOT NULL,
    result text NOT NULL,
    detail text,
    actor text
);

ALTER TABLE ONLY public.heartbeat_audit_summary
    ADD CONSTRAINT heartbeat_audit_summary_pkey PRIMARY KEY (secret_id);
