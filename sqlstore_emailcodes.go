package census

import "context"

// SpendEmailCode is the durable half of the spent-code record the VaultStore declares, over the
// census_spent_email_codes table InitSchema creates; MemStore is the semantic reference it has to
// match, and eachVault runs every case against both.
//
// The prune runs first, so the table holds only codes whose signature still opens. The insert IS the
// test, for the reason SpendStep's is: a conditional insert decided by the row's own primary key
// cannot admit two callers presenting one code together.
func (s *SQLVaultStore) SpendEmailCode(ctx context.Context, id string, expiresAt, now int64) (bool, error) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM census_spent_email_codes WHERE expires_at < ?`, now); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO census_spent_email_codes (id, expires_at)
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
