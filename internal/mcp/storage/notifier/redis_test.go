package notifier

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestRedisNotifier_CanSendReceiveByRole(t *testing.T) {
	nRecv := &RedisNotifier{role: config.RoleReceiver}
	assert.True(t, nRecv.CanReceive())
	assert.False(t, nRecv.CanSend())

	nSend := &RedisNotifier{role: config.RoleSender}
	assert.False(t, nSend.CanReceive())
	assert.True(t, nSend.CanSend())

	nBoth := &RedisNotifier{role: config.RoleBoth}
	assert.True(t, nBoth.CanReceive())
	assert.True(t, nBoth.CanSend())
}

func TestRedisNotifier_WatchAndNotify(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	logger := zap.NewNop()
	stream := "unla:mcp:updates"

	recv, err := NewRedisNotifier(logger, cnst.RedisClusterTypeSingle, mr.Addr(), "", "", "", "", "", 0, stream, config.RoleReceiver)
	assert.NoError(t, err)
	assert.NotNil(t, recv)

	// Start watching for updates
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := recv.Watch(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, ch)

	// Create a sender and push an update
	send, err := NewRedisNotifier(logger, cnst.RedisClusterTypeSingle, mr.Addr(), "", "", "", "", "", 0, stream, config.RoleSender)
	assert.NoError(t, err)
	cfg := &config.MCPConfig{Name: "cfg-1"}
	assert.NoError(t, send.NotifyUpdate(context.Background(), cfg))

	select {
	case got := <-ch:
		if assert.NotNil(t, got) {
			assert.Equal(t, "cfg-1", got.Name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for redis stream notification")
	}

	// Cancel and ensure channel closes soon after (allow up to 2s due to XREAD block)
	cancel()
	select {
	case _, ok := <-ch:
		// channel may deliver buffered values but must not block eventually
		_ = ok
	case <-time.After(2 * time.Second):
		t.Fatal("watch channel did not close in time")
	}
}

func TestRedisNotifier_Watch_NotReceiver(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	n, err := NewRedisNotifier(zap.NewNop(), cnst.RedisClusterTypeSingle, mr.Addr(), "", "", "", "", "", 0, "stream", config.RoleSender)
	assert.NoError(t, err)
	ch, werr := n.Watch(context.Background())
	assert.Nil(t, ch)
	assert.ErrorIs(t, werr, cnst.ErrNotReceiver)
}

func TestRedisNotifier_NotifyUpdate_NotSender(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	n, err := NewRedisNotifier(zap.NewNop(), cnst.RedisClusterTypeSingle, mr.Addr(), "", "", "", "", "", 0, "stream", config.RoleReceiver)
	assert.NoError(t, err)
	err = n.NotifyUpdate(context.Background(), &config.MCPConfig{Name: "x"})
	assert.ErrorIs(t, err, cnst.ErrNotSender)
}

func TestNewRedisNotifier_ConnectionError(t *testing.T) {
	// invalid address should cause ping failure
	n, err := NewRedisNotifier(zap.NewNop(), cnst.RedisClusterTypeSingle, "127.0.0.1:0", "", "", "", "", "", 0, "stream", config.RoleBoth)
	assert.Nil(t, n)
	assert.Error(t, err)
}

func TestNewRedisNotifier_SingleSeedCluster(t *testing.T) {
	mr := miniredis.RunT(t)
	n, err := NewRedisNotifier(zap.NewNop(), cnst.RedisClusterTypeCluster, mr.Addr(),
		"", "", "", "", "", 0, "cluster:updates", config.RoleBoth)
	require.NoError(t, err)
	defer n.client.Close()
	require.IsType(t, &redis.ClusterClient{}, n.client)
	ctx := context.Background()
	require.NoError(t, n.NotifyUpdate(ctx, &config.MCPConfig{Name: "one-seed"}))
	messages, err := n.client.XRange(ctx, "cluster:updates", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, messages, 1)
	require.Contains(t, messages[0].Values["config"], "one-seed")
}
