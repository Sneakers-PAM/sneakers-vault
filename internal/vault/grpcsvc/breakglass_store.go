// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	postgres "github.com/Bugs5382/go-postgres"
)

// breakGlassStore is the append-only ledger of emergency (break-glass) reveals.
// One row per BreakGlassSecret call: who broke glass on which secret, why, and
// whether the forced post-use rotation was scheduled / the owner notified. It
// never stores field values — the reveal is recorded as a high-severity audit
// event; this table is the operational record of the break-glass action itself.
type breakGlassStore struct{ db postgres.Querier }

func newBreakGlassStore(db postgres.Querier) *breakGlassStore { return &breakGlassStore{db: db} }

// Insert appends one break-glass event. Caller supplies the id (generated under
// the server lock) so the row is deterministic and never collides.
func (b *breakGlassStore) Insert(ctx context.Context, id, secretID, actorUserID, reason string, postRotationScheduled, notified bool) error {
	_, err := b.db.Exec(ctx,
		`INSERT INTO break_glass_events
		   (id, secret_id, actor_user_id, reason, post_rotation_scheduled, notified)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, secretID, actorUserID, reason, postRotationScheduled, notified)
	return err
}
