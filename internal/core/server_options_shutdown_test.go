package core

import (
	"context"
	"testing"

	"github.com/amoylab/unla/pkg/trace"
	"go.uber.org/zap"
)

func TestWithTraceCaptureOption(t *testing.T) {
	logger := zap.NewNop()
	cap := trace.CaptureConfig{}
	cap.DownstreamRequest.Enabled = true
	s, err := NewServer(logger, 0, nil, nil, nil, WithTraceCapture(cap))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if !s.traceCapture.DownstreamRequest.Enabled {
		t.Fatalf("expected trace capture enabled")
	}
}

func TestServerShutdown_NoTransports(t *testing.T) {
	logger := zap.NewNop()
	s, err := NewServer(logger, 0, nil, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
