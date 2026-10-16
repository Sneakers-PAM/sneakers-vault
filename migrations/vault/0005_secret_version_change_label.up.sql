-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- A version a type change produced carries its own description (old type ->
-- new type, fields added/renamed/carried over), instead of reading in history
-- as only "Changed: <field>" (#165). NULL for every other version.
ALTER TABLE public.secret_versions ADD COLUMN change_note text;
