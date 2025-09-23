package session

import (
	"context"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func newTestRedisStore(t *testing.T) (*RedisStore, *miniredis.Miniredis, context.CancelFunc) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.SessionRedisConfig{
		ClusterType: cnst.RedisClusterTypeSingle,
		Addr:        mr.Addr(),
		Topic:       "unla:sessions",
		Prefix:      "testsess",
		TTL:         5 * time.Second,
	}
	store, err := NewRedisStore(ctx, zap.NewNop(), cfg)
	if err != nil {
		cancel()
		mr.Close()
		t.Fatalf("failed to create RedisStore: %v", err)
	}
	return store, mr, cancel
}

func TestNewRedisStore_ConnectionError(t *testing.T) {
	ctx := context.Background()
	cfg := config.SessionRedisConfig{
		ClusterType: cnst.RedisClusterTypeSingle,
		Addr:        "127.0.0.1:0", // invalid
		Topic:       "x",
		Prefix:      "p",
		TTL:         time.Second,
	}
	s, err := NewRedisStore(ctx, zap.NewNop(), cfg)
	assert.Nil(t, s)
	assert.Error(t, err)
}

func TestRedisStore_RegisterGetListSendUnregister(t *testing.T) {
	store, mr, cancel := newTestRedisStore(t)
	defer func() {
		cancel()
		_ = store.Close()
		mr.Close()
	}()

	ctx := context.Background()
	meta := &Meta{ID: "sid-1", CreatedAt: time.Now(), Type: "sse"}

	// Register
	conn, err := store.Register(ctx, meta)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, "sid-1", conn.Meta().ID)

	// Get
	got, err := store.Get(ctx, "sid-1")
	assert.NoError(t, err)
	assert.Equal(t, "sid-1", got.Meta().ID)

	// List
	list, err := store.List(ctx)
	assert.NoError(t, err)
	assert.Len(t, list, 1)

	// Send should publish to stream and be delivered by handleUpdates
	msg := &Message{Event: "ping", Data: []byte("ok")}
	assert.NoError(t, conn.Send(ctx, msg))
	select {
	case recv := <-conn.EventQueue():
		if assert.NotNil(t, recv) {
			assert.Equal(t, "ping", recv.Event)
			assert.Equal(t, []byte("ok"), recv.Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for session event")
	}

	// Unregister
	assert.NoError(t, store.Unregister(ctx, "sid-1"))
	_, err = store.Get(ctx, "sid-1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	// Unregister unknown
	assert.ErrorIs(t, store.Unregister(ctx, "nope"), ErrSessionNotFound)
}
