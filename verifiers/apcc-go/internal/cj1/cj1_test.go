package cj1

import (
	"bytes"
	"testing"
)

func TestParseRejectsMalleabilityAndResourceAbuse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  []byte
		code string
	}{
		{"duplicate", []byte(`{"a":"x","a":"y"}`), "DUPLICATE_FIELD"},
		{"trailing", []byte(`{"a":"x"} `), "TRAILING_BYTES"},
		{"wrong type", []byte(`{"a":true}`), "WRONG_JSON_TYPE"},
		{"top-level malformed true delimiter", []byte(`truex`), "TRAILING_BYTES"},
		{"top-level malformed false delimiter", []byte(`falsex`), "TRAILING_BYTES"},
		{"top-level malformed null delimiter", []byte(`nullx`), "TRAILING_BYTES"},
		{"top-level malformed number delimiter", []byte(`1x`), "WRONG_JSON_TYPE"},
		{"nested malformed true delimiter", []byte(`{"a":truex}`), "MALFORMED_JSON"},
		{"nested malformed false delimiter", []byte(`{"a":falsex}`), "MALFORMED_JSON"},
		{"nested malformed null delimiter", []byte(`{"a":nullx}`), "MALFORMED_JSON"},
		{"nested malformed number delimiter", []byte(`{"a":1x}`), "WRONG_JSON_TYPE"},
		{"malformed boolean", []byte(`{"a":tru}`), "MALFORMED_JSON"},
		{"malformed negative", []byte(`{"a":-}`), "MALFORMED_JSON"},
		{"lone surrogate", []byte(`{"a":"\ud800"}`), "INVALID_UNICODE"},
		{"decomposed NFC", []byte("{\"a\":\"e\u0301\"}"), "INVALID_UNICODE"},
		{"noncanonical whitespace", []byte(`{"a": "x"}`), "NONCANONICAL_ENCODING"},
		{"noncanonical escaped solidus", []byte(`{"a":"\/"}`), "NONCANONICAL_ENCODING"},
		{"noncanonical escaped line separator", []byte(`{"a":"\u2028"}`), "NONCANONICAL_ENCODING"},
		{"non-ASCII key", []byte(`{"é":"x"}`), "UNKNOWN_FIELD"},
		{"depth", append(bytes.Repeat([]byte{'['}, 9), bytes.Repeat([]byte{']'}, 9)...), "DEPTH_LIMIT_EXCEEDED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.raw, MaxPayloadBytes)
			if err == nil || err.Code != test.code {
				t.Fatalf("got %v, want %s", err, test.code)
			}
		})
	}
}

func TestEncodeMatchesAPCCCJ1StringEscaping(t *testing.T) {
	t.Parallel()
	encoded, err := Encode(Object{"a": "<>&/\u2028", "b": "\b\n\t"})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("{\"a\":\"<>&/\u2028\",\"b\":\"\\b\\n\\t\"}")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("got %q, want %q", encoded, want)
	}
}
