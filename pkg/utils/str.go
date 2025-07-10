package utils

import (
	"regexp"
	"strings"
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
