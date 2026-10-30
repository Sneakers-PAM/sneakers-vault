-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- The built-ins (secret types, extension packs, connections, password
-- policies) this vault has already been given, one row per "<kind>:<id>". On
-- start-up the vault adds the built-ins a newer release ships, but only ones
-- with no row here, so a built-in an admin deleted is never put back.
CREATE TABLE public.builtin_ledger (
    id text NOT NULL,
    CONSTRAINT builtin_ledger_pkey PRIMARY KEY (id)
);
