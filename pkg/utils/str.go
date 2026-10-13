package utils

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

func FirstNonEmpty(str1, str2 string) string {
	if str1 != "" {
		return str1
	}
	if str2 != "" {
		return str2
	}
	return ""
}

func SplitByMultipleDelimiters(s string, delimiters ...string) []string {
	if len(delimiters) == 0 {
		return []string{s}
	}
	delimiterPattern := "[" + regexp.QuoteMeta(strings.Join(delimiters, "")) + "]"
	re := regexp.MustCompile(delimiterPattern)
	return re.Split(s, -1)
}

// TruncateUTF8 replaces invalid UTF-8 with U+FFFD and truncates at a complete
// character boundary within maxBytes. Nonpositive limits leave the length unlimited.
func TruncateUTF8(text string, maxBytes int) string {
	text = strings.ToValidUTF8(text, "\uFFFD")
	if maxBytes <= 0 || len(text) <= maxBytes {
		return text
	}
	for !utf8.RuneStart(text[maxBytes]) {
		maxBytes--
	}
	return text[:maxBytes]
}
