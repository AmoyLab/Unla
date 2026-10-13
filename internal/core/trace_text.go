package core

import (
	"strings"
	"unicode/utf8"
)

// traceText prepares captured text for OTLP string fields without changing tool payloads.
//
// +spec=`Trace text is valid UTF-8 and respects a positive byte limit; nonpositive limits are unlimited.`
// +why=`Splitting a UTF-8 code point or capturing arbitrary response bytes can reject an entire OTLP export batch.`
// +case:id=trace_utf8,desc=`Multibyte truncation and invalid input`,expect=`OTLP protobuf serialization succeeds`
func traceText(text string, maxBytes int) string {
	text = strings.ToValidUTF8(text, "\uFFFD")
	if maxBytes <= 0 || len(text) <= maxBytes {
		return text
	}
	for !utf8.RuneStart(text[maxBytes]) {
		maxBytes--
	}
	return text[:maxBytes]
}
