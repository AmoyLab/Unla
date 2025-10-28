package storage

import (
	"context"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
)

// Covers DBStore.List (with/without deleted) and DeleteVersion (non-active).
func TestDBStore_List_And_DeleteVersion(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()

	cfg1 := sampleConfig()
	cfg1.Name = "cfg1"
	cfg2 := sampleConfig()
	cfg2.Name = "cfg2"

	// Create two configs
	assert.NoError(t, s.Create(ctx, cfg1))
	assert.NoError(t, s.Create(ctx, cfg2))

	// List without deleted
	lst, err := s.List(ctx)
	assert.NoError(t, err)
	if assert.GreaterOrEqual(t, len(lst), 2) {
		names := []string{lst[0].Name, lst[1].Name}
		assert.Contains(t, names, "cfg1")
		assert.Contains(t, names, "cfg2")
	}

	// Create additional versions for cfg1 so we can delete a non-active one
	cfg1.Tools = append(cfg1.Tools, config.ToolConfig{Name: "tool-x"})
	assert.NoError(t, s.Update(ctx, cfg1)) // creates v2
	cfg1.Tools = append(cfg1.Tools, config.ToolConfig{Name: "tool-y"})
	assert.NoError(t, s.Update(ctx, cfg1)) // creates v3 (active)

	vers, err := s.ListVersions(ctx, cfg1.Tenant, cfg1.Name)
	assert.NoError(t, err)
	// Find a non-active version (prefer v2)
	nonActive := -1
	for _, v := range vers {
		if !v.IsActive {
			nonActive = v.Version
			break
		}
	}
	if nonActive == -1 {
		t.Fatalf("expected a non-active version to exist")
	}

	// Delete non-active version should succeed
	assert.NoError(t, s.DeleteVersion(ctx, cfg1.Tenant, cfg1.Name, nonActive))

	// Ensure it is gone from versions list
	vers2, err := s.ListVersions(ctx, cfg1.Tenant, cfg1.Name)
	assert.NoError(t, err)
	for _, v := range vers2 {
		if v.Version == nonActive {
			t.Fatalf("version %d should have been deleted", nonActive)
		}
	}

	// Soft delete cfg2 and verify List(includeDeleted=true) still returns it convertible
	assert.NoError(t, s.Delete(ctx, cfg2.Tenant, cfg2.Name))
	lstAll, err := s.List(ctx, true)
	assert.NoError(t, err)
	foundDeleted := false
	for _, it := range lstAll {
		if it.Name == cfg2.Name {
			foundDeleted = true
			break
		}
	}
	assert.True(t, foundDeleted, "expected deleted config present when includeDeleted=true")
}
