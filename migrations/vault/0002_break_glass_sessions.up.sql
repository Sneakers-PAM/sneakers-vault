-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Break-glass browse sessions: one row per session a site admin opens, and
-- the session each break-glass reveal was made in ('' for a single reveal
-- outside a session).
CREATE TABLE public.break_glass_sessions (
    id text NOT NULL,
    actor_user_id text NOT NULL,
    session_ref text NOT NULL,
    reason text NOT NULL,
    opened_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    ended_at timestamp with time zone,
    end_reason text DEFAULT ''::text NOT NULL,
    CONSTRAINT break_glass_sessions_pkey PRIMARY KEY (id)
);

CREATE INDEX break_glass_sessions_open ON public.break_glass_sessions USING btree (actor_user_id) WHERE (ended_at IS NULL);

CREATE INDEX break_glass_sessions_opened ON public.break_glass_sessions USING btree (opened_at DESC);

ALTER TABLE public.break_glass_events ADD COLUMN session_id text DEFAULT ''::text NOT NULL;

CREATE INDEX break_glass_events_session ON public.break_glass_events USING btree (session_id) WHERE (session_id <> ''::text);
