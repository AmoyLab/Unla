package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewInitializeRequest(t *testing.T) {
	params := InitializeRequestParams{
		ProtocolVersion: LatestProtocolVersion,
		Capabilities:    ClientCapabilitiesSchema{Roots: RootsCapabilitySchema{ListChanged: true}},
		ClientInfo:      ImplementationSchema{Name: "test", Version: "1.0"},
	}
	req := NewInitializeRequest(42, params)
	assert.Equal(t, JSPNRPCVersion, req.JSONRPC)
	assert.Equal(t, Initialize, req.Method)
	assert.Equal(t, int64(42), req.Id)

	// params should be marshaled JSON
	var decoded InitializeRequestParams
	err := json.Unmarshal(req.Params, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, params.ProtocolVersion, decoded.ProtocolVersion)
}

func TestNewPingRequest(t *testing.T) {
	req := NewPingRequest(7)
	assert.Equal(t, JSPNRPCVersion, req.JSONRPC)
	assert.Equal(t, Ping, req.Method)
	assert.Equal(t, int64(7), req.Id)
}

func TestNewJSONRPCBaseResultAndWithID(t *testing.T) {
	base := NewJSONRPCBaseResult()
	assert.Equal(t, JSPNRPCVersion, base.JSONRPC)
	assert.Equal(t, 0, base.ID)

	base2 := base.WithID(123)
	assert.Equal(t, 123, base2.ID)
}

func TestContentTypes(t *testing.T) {
	tc := &TextContent{}
	ic := &ImageContent{}
	ac := &AudioContent{}

	assert.Equal(t, TextContentType, tc.GetType())
	assert.Equal(t, ImageContentType, ic.GetType())
	assert.Equal(t, AudioContentType, ac.GetType())
}

func TestNewCallToolResultVariants(t *testing.T) {
	// raw content
	res := NewCallToolResult([]Content{&TextContent{Type: TextContentType, Text: "hi"}}, false)
	assert.False(t, res.IsError)
	if assert.Len(t, res.Content, 1) {
		_, ok := res.Content[0].(*TextContent)
		assert.True(t, ok)
	}

	// text
	rText := NewCallToolResultText("hello")
	assert.False(t, rText.IsError)
	if assert.Len(t, rText.Content, 1) {
		txt, ok := rText.Content[0].(*TextContent)
		assert.True(t, ok)
		assert.Equal(t, "hello", txt.Text)
	}

	// image
	rImg := NewCallToolResultImage("BASE64", "image/png")
	assert.False(t, rImg.IsError)
	if assert.Len(t, rImg.Content, 1) {
		img, ok := rImg.Content[0].(*ImageContent)
		assert.True(t, ok)
		assert.Equal(t, "BASE64", img.Data)
		assert.Equal(t, "image/png", img.MimeType)
	}

	// audio
	rAud := NewCallToolResultAudio("AUD64", "audio/mpeg")
	assert.False(t, rAud.IsError)
	if assert.Len(t, rAud.Content, 1) {
		aud, ok := rAud.Content[0].(*AudioContent)
		assert.True(t, ok)
		assert.Equal(t, "AUD64", aud.Data)
		assert.Equal(t, "audio/mpeg", aud.MimeType)
	}

	// error
	rErr := NewCallToolResultError("boom")
	assert.True(t, rErr.IsError)
	if assert.Len(t, rErr.Content, 1) {
		txt, ok := rErr.Content[0].(*TextContent)
		assert.True(t, ok)
		assert.Equal(t, "boom", txt.Text)
	}
}

func TestCallToolResultSerializesMeta(t *testing.T) {
	result := NewCallToolResultText("ok")
	result.Meta = map[string]any{
		"contains_pii": false,
		"source":       "tool-result",
	}

	data, err := json.Marshal(result)
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"content": [{"type": "text", "text": "ok"}],
		"isError": false,
		"_meta": {"contains_pii": false, "source": "tool-result"}
	}`, string(data))
}

func TestCallToolResultOmitsEmptyMeta(t *testing.T) {
	data, err := json.Marshal(NewCallToolResultText("ok"))

	assert.NoError(t, err)
	assert.NotContains(t, string(data), `"_meta"`)
}
