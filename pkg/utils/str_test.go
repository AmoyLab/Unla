package utils

import (
	"testing"
)
import "github.com/stretchr/testify/assert"

func TestSplitByMultipleDelimiters(t *testing.T) {
	input := "a,b;c"
	delimiters := []string{",", ";"}
	expected := []string{"a", "b", "c"}
	result := SplitByMultipleDelimiters(input, delimiters...)
	assert.Equal(t, expected, result)
	input = "a,b=c"
	expected = []string{"a", "b=c"}
	result = SplitByMultipleDelimiters(input, delimiters...)
	assert.Equal(t, expected, result)
	input = "a"
	expected = []string{"a"}
	result = SplitByMultipleDelimiters(input, delimiters...)
	assert.Equal(t, expected, result)
}
