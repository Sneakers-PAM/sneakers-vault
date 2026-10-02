-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Baseline schema for the workflow service. Forward-only from here: later
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


CREATE TABLE public.approval_comments (
    id text NOT NULL,
    request_id text NOT NULL,
    author_user_id text NOT NULL,
    body text NOT NULL,
    created_at text NOT NULL
);



CREATE TABLE public.approval_requests (
    id text NOT NULL,
    secret_id text NOT NULL,
    requested_by_user_id text NOT NULL,
    status integer DEFAULT 1 NOT NULL,
    requested_at text NOT NULL,
    resolved_at text DEFAULT ''::text NOT NULL,
    resolved_by_user_id text DEFAULT ''::text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    kind integer DEFAULT 0 NOT NULL,
    folder_id text DEFAULT ''::text NOT NULL,
    dest_parent_id text DEFAULT ''::text NOT NULL,
    folder_name text DEFAULT ''::text NOT NULL,
    dest_parent_name text DEFAULT ''::text NOT NULL
);



CREATE TABLE public.leases (
    id text NOT NULL,
    secret_id text NOT NULL,
    user_id text NOT NULL,
    issued_at text NOT NULL,
    expires_at text NOT NULL,
    returned boolean DEFAULT false NOT NULL,
    run_id text DEFAULT ''::text NOT NULL
);



ALTER TABLE ONLY public.approval_comments
    ADD CONSTRAINT approval_comments_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.approval_requests
    ADD CONSTRAINT approval_requests_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.leases
    ADD CONSTRAINT leases_pkey PRIMARY KEY (id);



CREATE INDEX approval_comments_request_idx ON public.approval_comments USING btree (request_id);



CREATE INDEX leases_secret_idx ON public.leases USING btree (secret_id);



-- One active lease per secret.
CREATE UNIQUE INDEX leases_one_active_per_secret ON public.leases USING btree (secret_id) WHERE (NOT returned);



CREATE INDEX leases_user_idx ON public.leases USING btree (user_id);



ALTER TABLE ONLY public.approval_comments
    ADD CONSTRAINT approval_comments_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.approval_requests(id) ON DELETE CASCADE;




