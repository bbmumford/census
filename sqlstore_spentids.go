/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import "context"

// SpendID is the durable half of the spent-id record the VaultStore declares, over the
// censusSpentIds table InitSchema creates; MemStore is the semantic reference it has to
// match, and eachVault runs every case against both.
//
// The prune runs first, so the table holds only tokens whose signature still opens. The insert IS the
// test, for the reason SpendStep's is: a conditional insert decided by the row's own primary key
// cannot admit two callers presenting one token together.
func (s *SQLVaultStore) SpendID(ctx context.Context, id string, expiresAt, now int64) (bool, error) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM censusSpentIds WHERE expiresAt < ?`, now); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO censusSpentIds (id, expiresAt)
		VALUES (?,?) ON CONFLICT(id) DO NOTHING`, id, expiresAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
