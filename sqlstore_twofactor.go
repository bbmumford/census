package census

import "context"

// The durable half of the spent-step record SpendStep and DeleteSpentSteps
// declare, over the censusSpentSteps table InitSchema creates. MemStore is the
// semantic reference these two have to match; eachVault runs every case against
// both.

// SpendStep inserts the step and reports whether this call placed it.
//
// The insert IS the test: a conditional insert decided by the row's own primary
// key cannot admit two callers, where a SELECT followed by an INSERT would answer
// first to both requests that arrive together with one stolen code. DO NOTHING is
// written rather than a driver-specific OR IGNORE so the one statement holds on
// every database/sql driver this store is opened over.
func (s *SQLVaultStore) SpendStep(ctx context.Context, partition, subject string, step, spentAt int64) (bool, error) {
	if partition == "" {
		return false, ErrUnscoped
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO censusSpentSteps (subject, step, partitionId, spentAt)
		VALUES (?,?,?,?) ON CONFLICT(subject, step) DO NOTHING`, subject, step, partition, spentAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// DeleteSpentSteps clears a subject's spent steps within one partition.
//
// A subject with nothing spent is not an error: the end state the caller asked
// for already holds, and DeleteTOTP calls this for every subject it removes a
// factor from, enrolled steps or not.
func (s *SQLVaultStore) DeleteSpentSteps(ctx context.Context, partition, subject string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM censusSpentSteps
		WHERE (? <> '' AND partitionId = ?) AND subject = ?`, partition, partition, subject)
	return err
}
