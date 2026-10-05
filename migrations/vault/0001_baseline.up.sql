-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Baseline schema for the vault service. Forward-only from here: later
-- changes are new numbered migrations starting at 0002.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.break_glass_events (
    id text NOT NULL,
    secret_id text NOT NULL,
    actor_user_id text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    post_rotation_scheduled boolean DEFAULT false NOT NULL,
    notified boolean DEFAULT false NOT NULL
);

CREATE TABLE public.connections (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.connector_contacts (
    worker_id text NOT NULL,
    version text DEFAULT ''::text NOT NULL,
    commit text DEFAULT ''::text NOT NULL,
    last_contact_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.extension_catalog (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.folder_rules (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.folders (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.heartbeat_schedule (
    secret_id text NOT NULL,
    next_heartbeat_at timestamp with time zone DEFAULT now() NOT NULL,
    interval_seconds integer DEFAULT 300 NOT NULL,
    consecutive_unreachable integer DEFAULT 0 NOT NULL,
    claimed_until timestamp with time zone,
    last_manual_at timestamp with time zone
);

CREATE TABLE public.kek_keyring (
    ref text NOT NULL,
    wrapped_key bytea NOT NULL,
    root_ref text NOT NULL,
    active boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone
);

CREATE TABLE public.password_policies (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.raci_rules (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.rotation_schedule (
    secret_id text NOT NULL,
    next_rotation_at timestamp with time zone,
    interval_days integer DEFAULT 0 NOT NULL,
    claimed_until timestamp with time zone,
    state integer DEFAULT 0 NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    consecutive_failures integer DEFAULT 0 NOT NULL
);

CREATE TABLE public.secret_records (
    secret_id text NOT NULL,
    record jsonb NOT NULL
);

CREATE TABLE public.secret_types (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.secret_use_grants (
    id text NOT NULL,
    user_id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.secret_uses (
    id text NOT NULL,
    user_id text NOT NULL,
    state integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.secret_versions (
    secret_id text NOT NULL,
    version_no integer NOT NULL,
    record jsonb NOT NULL,
    active boolean DEFAULT false NOT NULL,
    staged boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL
);

CREATE TABLE public.secrets (
    id text NOT NULL,
    data jsonb NOT NULL
);

CREATE TABLE public.security_settings (
    id integer DEFAULT 1 NOT NULL,
    data jsonb NOT NULL,
    CONSTRAINT security_settings_singleton CHECK ((id = 1))
);

CREATE TABLE public.target_raci_rules (
    id text NOT NULL,
    target_id text NOT NULL,
    data jsonb NOT NULL
);

-- SSH host key pins per target: the public keys the SSH broker accepts for
-- the target, in saved order, each with its SHA256 fingerprint. Public keys,
-- not secrets. Replaced as a whole on every state snapshot, like
-- target_raci_rules, so there is no foreign key to targets.
CREATE TABLE public.target_ssh_host_keys (
    target_id text NOT NULL,
    ordinal integer NOT NULL,
    public_key text NOT NULL,
    fingerprint text NOT NULL
);

CREATE TABLE public.targets (
    id text NOT NULL,
    data jsonb NOT NULL
);

ALTER TABLE ONLY public.break_glass_events
    ADD CONSTRAINT break_glass_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.connector_contacts
    ADD CONSTRAINT connector_contacts_pkey PRIMARY KEY (worker_id);

ALTER TABLE ONLY public.extension_catalog
    ADD CONSTRAINT extension_catalog_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.folder_rules
    ADD CONSTRAINT folder_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.heartbeat_schedule
    ADD CONSTRAINT heartbeat_schedule_pkey PRIMARY KEY (secret_id);

ALTER TABLE ONLY public.kek_keyring
    ADD CONSTRAINT kek_keyring_pkey PRIMARY KEY (ref);

ALTER TABLE ONLY public.password_policies
    ADD CONSTRAINT password_policies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.raci_rules
    ADD CONSTRAINT raci_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rotation_schedule
    ADD CONSTRAINT rotation_schedule_pkey PRIMARY KEY (secret_id);

ALTER TABLE ONLY public.secret_records
    ADD CONSTRAINT secret_records_pkey PRIMARY KEY (secret_id);

ALTER TABLE ONLY public.secret_types
    ADD CONSTRAINT secret_types_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.secret_use_grants
    ADD CONSTRAINT secret_use_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.secret_uses
    ADD CONSTRAINT secret_uses_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.secret_versions
    ADD CONSTRAINT secret_versions_pkey PRIMARY KEY (secret_id, version_no);

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.security_settings
    ADD CONSTRAINT security_settings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.target_raci_rules
    ADD CONSTRAINT target_raci_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.target_ssh_host_keys
    ADD CONSTRAINT target_ssh_host_keys_pkey PRIMARY KEY (target_id, ordinal);

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (id);

CREATE INDEX break_glass_events_secret ON public.break_glass_events USING btree (secret_id);

CREATE INDEX heartbeat_schedule_due ON public.heartbeat_schedule USING btree (next_heartbeat_at);

CREATE UNIQUE INDEX kek_keyring_one_active ON public.kek_keyring USING btree (active) WHERE active;

CREATE INDEX rotation_schedule_due ON public.rotation_schedule USING btree (next_rotation_at);

CREATE INDEX secret_use_grants_user_idx ON public.secret_use_grants USING btree (user_id);

CREATE INDEX secret_uses_pending_idx ON public.secret_uses USING btree (user_id) WHERE (state = 1);

CREATE INDEX secret_versions_active ON public.secret_versions USING btree (secret_id) WHERE active;

CREATE UNIQUE INDEX secret_versions_one_staged ON public.secret_versions USING btree (secret_id) WHERE staged;

CREATE INDEX target_raci_rules_target_idx ON public.target_raci_rules USING btree (target_id);

CREATE INDEX target_ssh_host_keys_fingerprint_idx ON public.target_ssh_host_keys USING btree (fingerprint);
