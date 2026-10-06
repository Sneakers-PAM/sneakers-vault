-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

DROP INDEX IF EXISTS public.break_glass_events_session;
ALTER TABLE public.break_glass_events DROP COLUMN IF EXISTS session_id;
DROP TABLE IF EXISTS public.break_glass_sessions;
