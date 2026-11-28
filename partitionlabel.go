/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package census

import (
	"context"
	"errors"
)

// The attributes a partition's entity holds the word its people see for the
// partition in: PartitionLabelAttr the singular and PartitionLabelPluralAttr the
// plural ("Team" and "Teams", say). An entity holding neither has no word of its
// own, and the reader chooses the word shown.
const (
	PartitionLabelAttr       = "label"
	PartitionLabelPluralAttr = "labelPlural"
)

// ErrPartitionLabelIncomplete is SetPartitionLabel's refusal of a word given
// without its plural, or a plural without its word: a partition holds both or
// neither.
var ErrPartitionLabelIncomplete = errors.New("census: a partition label is set with its plural, or both are cleared")

// PartitionLabel answers the word partition's entity holds and its plural, both
// empty for a partition whose word was never set or was cleared. A partition the
// graph does not hold answers the store's nexus.ErrNotFound, as PartitionName
// does.
func (s *GraphService) PartitionLabel(ctx context.Context, partition string) (singular, plural string, err error) {
	e, err := s.graph.GetEntity(ctx, partition)
	if err != nil {
		return "", "", err
	}
	return e.Attrs[PartitionLabelAttr], e.Attrs[PartitionLabelPluralAttr], nil
}

// SetPartitionLabel writes singular and plural as partition's word and its
// plural, keeping every other attribute the entity holds, in one transaction as
// RenamePartition writes the name; both empty clears the word. One without the
// other is ErrPartitionLabelIncomplete and a partition the graph does not hold
// is nexus.ErrNotFound; neither writes anything. The caller checks who may set
// it and what a word may be: census stores what it is given.
func (s *GraphService) SetPartitionLabel(ctx context.Context, partition, singular, plural string) error {
	if (singular == "") != (plural == "") {
		return ErrPartitionLabelIncomplete
	}
	return s.Atomic(ctx, func(tx *GraphTx) error {
		e, err := tx.GetEntity(ctx, partition)
		if err != nil {
			return err
		}
		labelled := e.Clone()
		if labelled.Attrs == nil {
			labelled.Attrs = map[string]string{}
		}
		if singular == "" {
			delete(labelled.Attrs, PartitionLabelAttr)
			delete(labelled.Attrs, PartitionLabelPluralAttr)
		} else {
			labelled.Attrs[PartitionLabelAttr] = singular
			labelled.Attrs[PartitionLabelPluralAttr] = plural
		}
		return tx.PutEntity(ctx, labelled)
	})
}
