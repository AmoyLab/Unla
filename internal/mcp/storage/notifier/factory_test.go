package notifier

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewNotifier_UnknownType(t *testing.T) {
	_, err := NewNotifier(context.Background(), zap.NewNop(), &config.NotifierConfig{Type: "unknown"})
	assert.Error(t, err)
}

func TestNewNotifier_KnownTypes(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// signal (provide dummy pid path so constructor doesn't panic)
	n1, err := NewNotifier(ctx, logger, &config.NotifierConfig{Type: string(TypeSignal), Role: string(config.RoleBoth), Signal: config.SignalConfig{PID: "/tmp/unla-test.pid"}})
	assert.NoError(t, err)
	assert.True(t, n1.CanReceive())

	// api sender
	n2, err := NewNotifier(ctx, logger, &config.NotifierConfig{Type: string(TypeAPI), Role: string(config.RoleSender)})
	assert.NoError(t, err)
	assert.True(t, n2.CanSend())

	// redis using invalid address should return error
	n3, err := NewNotifier(ctx, logger, &config.NotifierConfig{
		Type:  string(TypeRedis),
		Role:  string(config.RoleBoth),
		Redis: config.RedisConfig{Addr: "127.0.0.1:0"},
	})
	assert.Nil(t, n3)
	assert.Error(t, err)

	// composite without redis addr should still construct (provide dummy pid)
	n4, err := NewNotifier(ctx, logger, &config.NotifierConfig{Type: string(TypeComposite), Role: string(config.RoleBoth), Signal: config.SignalConfig{PID: "/tmp/unla-test.pid"}})
	assert.NoError(t, err)
	// type string contains Composite for sanity
	typeStr := fmt.Sprintf("%T", n4)
	assert.True(t, strings.Contains(typeStr, "Composite"))
}
