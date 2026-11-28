/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"testing"
)

// Every census table holding a partition stores it in a column named
// partitionId, the name every partition-holding field, key and column takes, and
// no table keeps a column named partition beside or instead of it. The vault's
// credential, spent-step and API-key tables and the transfer log are read.
func TestEveryPartitionColumnIsNamedPartitionId(t *testing.T) {
	ctx := context.Background()
	db := fileDB(t)
	if err := NewSQLVaultStore(db).InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := NewSQLTransferLog(db).InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"censusCredentials", "censusSpentSteps", "censusApiKeys", "censusTransfers"} {
		rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		cols := map[string]bool{}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols[c] = true
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if !cols["partitionId"] || cols["partition"] {
			t.Errorf("%s columns %v: want partitionId and no partition", table, cols)
		}
	}
}
