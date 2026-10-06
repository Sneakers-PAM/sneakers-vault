-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Secrets gain a manual position in their folder (Secret.position, stored in
-- the record's JSON). Backfill it for every active secret, 1-based within each
-- folder, by name (case-insensitive) and then id. Retired secrets have none.
WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY COALESCE(data->>'folderId', '')
               ORDER BY lower(COALESCE(data->>'name', '')), id
           ) AS pos
    FROM public.secrets
    WHERE COALESCE((data->>'retired')::boolean, false) = false
)
UPDATE public.secrets s
SET data = jsonb_set(s.data, '{position}', to_jsonb(r.pos))
FROM ranked r
WHERE s.id = r.id;

UPDATE public.secrets
SET data = data - 'position'
WHERE COALESCE((data->>'retired')::boolean, false) = true;
