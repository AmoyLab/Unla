package utils

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestFirstNonEmpty(t *testing.T) {
	t.Run("returns first when first is non-empty", func(t *testing.T) {
		assert.Equal(t, "a", FirstNonEmpty("a", "b"))
	})

	t.Run("returns second when first is empty", func(t *testing.T) {
		assert.Equal(t, "b", FirstNonEmpty("", "b"))
	})

	t.Run("returns empty when both are empty", func(t *testing.T) {
		assert.Equal(t, "", FirstNonEmpty("", ""))
	})

	t.Run("treats whitespace as non-empty", func(t *testing.T) {
		assert.Equal(t, " ", FirstNonEmpty(" ", "b"))
	})
}

func TestSplitByMultipleDelimiters(t *testing.T) {
	// no delimiters -> whole string
	got := SplitByMultipleDelimiters("a,b;c")
	assert.Equal(t, []string{"a,b;c"}, got)

	got = SplitByMultipleDelimiters("a,b;c|d", ",", ";", "|")
	assert.Equal(t, []string{"a", "b", "c", "d"}, got)
}

func TestTruncateUTF8(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string
		limit            int
	}{
		{"empty", "", "", 1},
		{"ASCII", "abcdef", "abc", 3},
		{"exact boundary", "中", "中", 3},
		{"partial Chinese", "中文", "中", 4},
		{"no complete character", "中", "", 2},
		{"partial emoji", "a😀b", "a", 4},
		{"complete emoji", "a😀b", "a😀", 5},
		{"replacement byte budget", "a\xffb", "a", 3},
		{"replacement fits", "a\xffb", "a�", 4},
		{"valid replacement character", "�", "�", 3},
		{"invalid prefix", "\xffabc", "�abc", 0},
		{"invalid suffix", "abc\xff", "abc�", -1},
		{"incomplete input", "\xe4\xb8", "�", 0},
		{"unlimited Unicode", "中文😀", "中文😀", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := TruncateUTF8(tc.text, tc.limit)
			assert.Equal(t, tc.want, got)
			assert.True(t, utf8.ValidString(got))
			if tc.limit > 0 {
				assert.LessOrEqual(t, len(got), tc.limit)
			}
		})
	}
}
