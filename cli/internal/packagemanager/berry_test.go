package packagemanager

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_ParseBerryResoltuion(t *testing.T) {
	type testCase struct {
		input    string
		expected berryResolution
		errMsg   string
	}
	testCases := []testCase{
		{
			input:    "relay-compiler",
			expected: berryResolution{descriptor: berrySpecifier{fullName: "relay-compiler"}},
		},
		{
			input:    "webpack/memory-fs",
			expected: berryResolution{from: berrySpecifier{fullName: "webpack"}, descriptor: berrySpecifier{fullName: "memory-fs"}},
		},
		{
			input:    "@babel/core/json5",
			expected: berryResolution{from: berrySpecifier{fullName: "@babel/core"}, descriptor: berrySpecifier{fullName: "json5"}},
		},
		{
			input:    "@babel/core/@babel/generator",
			expected: berryResolution{from: berrySpecifier{fullName: "@babel/core"}, descriptor: berrySpecifier{fullName: "@babel/generator"}},
		},
		{
			input:    "@babel/core@npm:7.0.0/@babel/generator",
			expected: berryResolution{from: berrySpecifier{fullName: "@babel/core", description: "npm:7.0.0"}, descriptor: berrySpecifier{fullName: "@babel/generator"}},
		},
	}

	for _, tc := range testCases {
		res, err := parseBerryResolution(tc.input)
		if tc.errMsg == "" {
			assert.NilError(t, err, "Unexpected err when parsing: %s", tc.input)
			assert.Equal(t, res, tc.expected)
		} else {
			assert.ErrorContains(t, err, tc.errMsg)
		}
	}
}
