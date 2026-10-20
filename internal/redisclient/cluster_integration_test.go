package redisclient_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amoylab/unla/internal/auth/storage"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/internal/mcp/storage/notifier"
	"github.com/amoylab/unla/internal/redisclient"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestSingleSeedClusterAcrossShards exercises the real stores against a disposable
// multi-node cluster. Set UNLA_TEST_REDIS_CLUSTER_ADDR to one seed to enable it.
func TestSingleSeedClusterAcrossShards(t *testing.T) {
	addr := os.Getenv("UNLA_TEST_REDIS_CLUSTER_ADDR")
	if addr == "" {
		t.Skip("set UNLA_TEST_REDIS_CLUSTER_ADDR to a disposable Redis Cluster seed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := redisclient.New("cluster", redis.UniversalOptions{Addrs: []string{addr}})
	require.NoError(t, err)
	defer client.Close()
	seed := redis.NewClient(&redis.Options{Addr: addr})
	defer seed.Close()

	// Select keys that a plain client connected to the seed cannot serve.
	var tag string
	for i := 0; i < 100; i++ {
		candidate := fmt.Sprintf("{unla-%d-%d}", time.Now().UnixNano(), i)
		err := seed.Get(ctx, candidate).Err()
		if err != nil && strings.HasPrefix(err.Error(), "MOVED ") {
			tag = candidate
			break
		}
		require.ErrorIs(t, err, redis.Nil)
	}
	require.NotEmpty(t, tag, "the cluster must have a shard outside the seed")
	t.Logf("seed %s returns MOVED for test hash tag %s", addr, tag)

	prefix, sessionTopic, notifyTopic := tag+":session", tag+":events", tag+":config"
	id := "single-seed"
	oauthID := tag + ":client"
	keys := []string{prefix + ":" + id, prefix + ":ids", sessionTopic, notifyTopic, "oauth:client:" + oauthID}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		for _, key := range keys {
			require.NoError(t, client.Del(cleanupCtx, key).Err())
		}
	}()

	sessions, err := session.NewRedisStore(ctx, zap.NewNop(), config.SessionRedisConfig{
		ClusterType: "cluster", Addr: addr, Prefix: prefix, Topic: sessionTopic, TTL: time.Minute,
	})
	require.NoError(t, err)
	defer sessions.Close()
	conn, err := sessions.Register(ctx, &session.Meta{ID: id, Type: "sse", CreatedAt: time.Now()})
	require.NoError(t, err)
	loaded, err := sessions.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, id, loaded.Meta().ID)
	message := &session.Message{Event: "cluster-test", Data: []byte("delivered")}
	require.NoError(t, conn.Send(ctx, message))
	select {
	case got := <-conn.EventQueue():
		require.Equal(t, message.Event, got.Event)
		require.Equal(t, message.Data, got.Data)
	case <-ctx.Done():
		t.Fatal("session event was not delivered")
	}
	require.NoError(t, sessions.Unregister(ctx, id))

	notifications, err := notifier.NewRedisNotifier(zap.NewNop(), "cluster", addr,
		"", "", "", "", "", 0, notifyTopic, config.RoleBoth)
	require.NoError(t, err)
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	updates, err := notifications.Watch(watchCtx)
	require.NoError(t, err)
	expected := &config.MCPConfig{Name: "single-seed-cluster"}
	// Watch starts asynchronously at "$". Repeated idempotent config notifications
	// avoid treating its pre-existing readiness behavior as part of mode selection.
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	received := false
	for !received {
		select {
		case <-ticker.C:
			require.NoError(t, notifications.NotifyUpdate(ctx, expected))
		case got := <-updates:
			require.NotNil(t, got)
			require.Equal(t, expected.Name, got.Name)
			received = true
		case <-ctx.Done():
			t.Fatal("configuration notification was not delivered")
		}
	}

	oauth, err := storage.NewRedisStorage("cluster", addr, "", "", "", "", "", 0)
	require.NoError(t, err)
	require.NoError(t, oauth.CreateClient(ctx, &storage.Client{ID: oauthID}))
	registered, err := oauth.GetClient(ctx, oauthID)
	require.NoError(t, err)
	require.Equal(t, oauthID, registered.ID)
	require.NoError(t, oauth.DeleteClient(ctx, oauthID))

	// A dead first seed must not prevent discovery through the remaining seed.
	fallback, err := redisclient.New("cluster", redis.UniversalOptions{
		Addrs: []string{"127.0.0.1:0", addr}, DialTimeout: 100 * time.Millisecond,
	})
	require.NoError(t, err)
	defer fallback.Close()
	require.NoError(t, fallback.Set(ctx, prefix+":"+id, "fallback", time.Minute).Err())
	value, err := fallback.Get(ctx, prefix+":"+id).Result()
	require.NoError(t, err)
	require.Equal(t, "fallback", value)
}
