/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
)

// ErrPartitionNameRequired is RenamePartition's refusal of an empty name: a
// partition is renamed to a name, and clearing one is not a rename.
var ErrPartitionNameRequired = errors.New("census: a partition name is required")

// PartitionName answers the name partition's entity holds (PartitionNameAttr):
// the name it was founded with or last renamed to, empty for a partition
// founded without one. A partition the graph does not hold answers the store's
// nexus.ErrNotFound, so a caller tells an unnamed partition from an unknown one.
func (s *GraphService) PartitionName(ctx context.Context, partition string) (string, error) {
	e, err := s.graph.GetEntity(ctx, partition)
	if err != nil {
		return "", err
	}
	return e.Attrs[PartitionNameAttr], nil
}

// RenamePartition writes name as partition's PartitionNameAttr, keeping every
// other attribute the entity holds, in one transaction so two renames do not
// interleave a read of one with the write of the other. An empty name is
// ErrPartitionNameRequired and a partition the graph does not hold is
// nexus.ErrNotFound; neither writes anything. It records nothing on the
// transfer log, which records relationships: the identity operation that
// renames a partition records the change on the partition's audit trail.
func (s *GraphService) RenamePartition(ctx context.Context, partition, name string) error {
	if name == "" {
		return ErrPartitionNameRequired
	}
	return s.Atomic(ctx, func(tx *GraphTx) error {
		e, err := tx.GetEntity(ctx, partition)
		if err != nil {
			return err
		}
		renamed := e.Clone()
		if renamed.Attrs == nil {
			renamed.Attrs = map[string]string{}
		}
		renamed.Attrs[PartitionNameAttr] = name
		return tx.PutEntity(ctx, renamed)
	})
}
