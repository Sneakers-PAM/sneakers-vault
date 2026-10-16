-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Secrets gain a list of attached targets (Secret.target_ids), replacing the
-- single target_id for attach-to-many-targets (#168). Backfill target_ids as
-- a one-item array from the existing target_id; target_id itself is left
-- untouched and stays readable until every consumer moves to the list.
UPDATE public.secrets
SET data = jsonb_set(data, '{targetIds}', jsonb_build_array(data->>'targetId'))
WHERE COALESCE(data->>'targetId', '') <> '';
