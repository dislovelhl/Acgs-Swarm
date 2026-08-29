package cj1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRFC8785AppendixBNumbersAreOutsideAPCCCJ1(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "experiments/apcc-1/rfc8785/appendix-b-numbers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Samples []string `json:"samples"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Samples) == 0 {
		t.Fatal("empty appendix B sample list")
	}
	for _, sample := range body.Samples {
		_, parseErr := Parse([]byte(sample), MaxPayloadBytes)
		if parseErr == nil || parseErr.Code != "WRONG_JSON_TYPE" {
			t.Fatalf("sample %q: got %v, want WRONG_JSON_TYPE (CJ1 is not RFC 8785 JCS)", sample, parseErr)
		}
	}
}
