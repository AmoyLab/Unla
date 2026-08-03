package core

import (
	"context"
	"errors"

	"github.com/amoylab/unla/internal/mcp/session"
)

const streamableStatelessType = "streamable-stateless"

type statelessConnection struct {
	meta *session.Meta
}

func newStatelessConnection(meta *session.Meta) session.Connection {
	return &statelessConnection{meta: meta}
}

func (c *statelessConnection) EventQueue() <-chan *session.Message {
	return nil
}

func (c *statelessConnection) Send(context.Context, *session.Message) error {
	return errors.New("stateless connection does not support queued messages")
}

func (c *statelessConnection) Close(context.Context) error {
	return nil
}

func (c *statelessConnection) Meta() *session.Meta {
	return c.meta
}

func isStreamableStateless(conn session.Connection) bool {
	return conn != nil && conn.Meta() != nil && conn.Meta().Type == streamableStatelessType
}
