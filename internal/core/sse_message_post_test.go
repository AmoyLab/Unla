package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/pkg/mcp"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type testFakeConn struct{ meta *session.Meta }

func (f *testFakeConn) EventQueue() <-chan *session.Message                  { return make(chan *session.Message) }
func (f *testFakeConn) Send(ctx context.Context, msg *session.Message) error { return nil }
func (f *testFakeConn) Close(ctx context.Context) error                      { return nil }
func (f *testFakeConn) Meta() *session.Meta                                  { return f.meta }

type testFakeConnErr struct{ meta *session.Meta }

func (f *testFakeConnErr) EventQueue() <-chan *session.Message { return make(chan *session.Message) }
func (f *testFakeConnErr) Send(ctx context.Context, msg *session.Message) error {
	return fmt.Errorf("send error")
}
func (f *testFakeConnErr) Close(ctx context.Context) error { return nil }
func (f *testFakeConnErr) Meta() *session.Meta             { return f.meta }

func TestHandleMessage_MissingSessionID(t *testing.T) {
	logger := zap.NewNop()
	s, err := NewServer(logger, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/x/message", nil)

	s.handleMessage(c)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandlePostMessage_BasicValidation(t *testing.T) {
	logger := zap.NewNop()
	s, err := NewServer(logger, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// nil connection
	{
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/x/message", nil)
		s.handlePostMessage(c, nil)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", w.Code)
		}
	}

	// invalid content type
	{
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/x/message", bytes.NewBufferString("{}"))
		req.Header.Set("Content-Type", "text/plain")
		c.Request = req
		s.handlePostMessage(c, &testFakeConn{meta: &session.Meta{ID: "sid"}})
		if w.Code != http.StatusNotAcceptable {
			t.Fatalf("expected 406, got %d", w.Code)
		}
	}

	// invalid json
	{
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodPost, "/x/message", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		s.handlePostMessage(c, &testFakeConn{meta: &session.Meta{ID: "sid"}})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	}
}

func TestSendErrorResponse_SendFailureAccepted(t *testing.T) {
	logger := zap.NewNop()
	s, err := NewServer(logger, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/x/message", nil)

	conn := &testFakeConnErr{meta: &session.Meta{ID: "sid"}}
	s.sendErrorResponse(c, conn, mcp.JSONRPCRequest{Id: "1", Method: "demo"}, "oops")
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}
