package census

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// openDB opens a fresh in-memory SQLite DB pinned to one connection (so the :memory: db is shared
// across statements) and closes it at test end.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	})
	return db
}

// eachVault runs a case against both the MemStore reference and the durable SQLVaultStore, holding the
// SQL store to the exact semantics MemStore defines.
func eachVault(t *testing.T, fn func(t *testing.T, store VaultStore)) {
	t.Helper()
	t.Run("mem", func(t *testing.T) { fn(t, NewMemStore()) })
	t.Run("sql", func(t *testing.T) {
		s := NewSQLVaultStore(openDB(t))
		if err := s.InitSchema(ctx); err != nil {
			t.Fatalf("InitSchema: %v", err)
		}
		fn(t, s)
	})
}

// eachLog runs a case against both the MemTransferLog reference and the durable SQLTransferLog.
func eachLog(t *testing.T, fn func(t *testing.T, log TransferLog)) {
	t.Helper()
	t.Run("mem", func(t *testing.T) { fn(t, NewMemTransferLog()) })
	t.Run("sql", func(t *testing.T) {
		l := NewSQLTransferLog(openDB(t))
		if err := l.InitSchema(ctx); err != nil {
			t.Fatalf("InitSchema: %v", err)
		}
		fn(t, l)
	})
}
