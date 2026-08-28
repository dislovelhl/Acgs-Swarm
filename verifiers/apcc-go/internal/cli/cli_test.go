package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/acgs/apcc-go-verifier/internal/cj1"
)

type manifestInputs struct {
	RequestNonce            string `json:"request_nonce"`
	NowMS                   string `json:"now_ms"`
	HighestTrustLogSequence string `json:"highest_trust_log_sequence"`
	HighestTrustLogHead     string `json:"highest_trust_log_head"`
	MaximumStalenessMS      string `json:"maximum_staleness_ms"`
}

type manifestVector struct {
	Name            string            `json:"name"`
	Mode            string            `json:"mode"`
	Certificate     string            `json:"certificate"`
	Trust           string            `json:"trust"`
	AuthorityStatus string            `json:"authority_status"`
	CurrentInputs   manifestInputs    `json:"current_inputs"`
	Predecessors    map[string]string `json:"predecessors"`
	CausalLimits    map[string]int    `json:"causal_limits"`
	ExpectedCode    string            `json:"expected_code"`
}

type fixtureManifest struct {
	ProtocolVersion string           `json:"protocol_version"`
	Vectors         []manifestVector `json:"vectors"`
}

func fixtureRoot(t testing.TB) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate APCC CLI test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "tests", "fixtures", "apcc", "v1"))
}

func loadManifest(t testing.TB) (string, fixtureManifest) {
	t.Helper()
	root := fixtureRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func vectorNamed(t testing.TB, manifest fixtureManifest, name string) manifestVector {
	t.Helper()
	for _, vector := range manifest.Vectors {
		if vector.Name == name {
			return vector
		}
	}
	t.Fatalf("manifest vector %q not found", name)
	return manifestVector{}
}

func causalLeafVector(t testing.TB, manifest fixtureManifest) manifestVector {
	t.Helper()
	vector := vectorNamed(t, manifest, "valid-causal-chain")
	for _, reference := range vector.Predecessors {
		vector.Certificate = reference
		vector.Predecessors = nil
		vector.CausalLimits = nil
		return vector
	}
	t.Fatal("valid causal vector has no predecessor leaf")
	return manifestVector{}
}

func artifactPath(root, reference string) string {
	return filepath.Join(root, filepath.FromSlash(reference))
}

func auditArtifact(t testing.TB, root, reference string) []byte {
	t.Helper()
	raw, err := os.ReadFile(artifactPath(root, reference))
	if err != nil {
		t.Fatalf("read %q: %v", reference, err)
	}
	want := strings.TrimSuffix(filepath.Base(reference), ".json")
	actual := sha256.Sum256(raw)
	if hex.EncodeToString(actual[:]) != want {
		t.Fatalf("content address mismatch for %q", reference)
	}
	return raw
}

func vectorArguments(root string, vector manifestVector) []string {
	arguments := []string{
		vector.Mode,
		"--certificate", artifactPath(root, vector.Certificate),
		"--trust", artifactPath(root, vector.Trust),
	}
	if vector.Mode == "causal" {
		digests := make([]string, 0, len(vector.Predecessors))
		for digest := range vector.Predecessors {
			digests = append(digests, digest)
		}
		sort.Strings(digests)
		for _, digest := range digests {
			arguments = append(arguments, "--predecessor", digest+"="+artifactPath(root, vector.Predecessors[digest]))
		}
		for _, limit := range []struct {
			field string
			flag  string
		}{
			{field: "max_depth", flag: "--max-depth"},
			{field: "max_certificates", flag: "--max-certificates"},
			{field: "max_total_bytes", flag: "--max-total-bytes"},
		} {
			if value, ok := vector.CausalLimits[limit.field]; ok {
				arguments = append(arguments, limit.flag, strconv.Itoa(value))
			}
		}
	}
	if vector.Mode == "current" {
		if vector.AuthorityStatus != "" {
			arguments = append(arguments, "--authority-status", artifactPath(root, vector.AuthorityStatus))
		}
		arguments = append(arguments,
			"--request-nonce", vector.CurrentInputs.RequestNonce,
			"--now-ms", vector.CurrentInputs.NowMS,
			"--highest-trust-log-sequence", vector.CurrentInputs.HighestTrustLogSequence,
			"--highest-trust-log-head", vector.CurrentInputs.HighestTrustLogHead,
			"--maximum-staleness-ms", vector.CurrentInputs.MaximumStalenessMS,
		)
	}
	return arguments
}

func expectedDigest(t testing.TB, root string, vector manifestVector) string {
	t.Helper()
	if vector.ExpectedCode != "OK" {
		return ""
	}
	var envelope struct {
		PayloadSHA256 string `json:"payload_sha256"`
	}
	if err := json.Unmarshal(auditArtifact(t, root, vector.Certificate), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.PayloadSHA256
}

func TestManifestVectorsExerciseFullCLIContract(t *testing.T) {
	root, manifest := loadManifest(t)
	if manifest.ProtocolVersion != protocolVersion {
		t.Fatalf("manifest protocol = %q", manifest.ProtocolVersion)
	}
	if len(manifest.Vectors) != 126 {
		t.Fatalf("manifest vectors = %d, want 126", len(manifest.Vectors))
	}
	for _, vector := range manifest.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			auditArtifact(t, root, vector.Certificate)
			auditArtifact(t, root, vector.Trust)
			if vector.AuthorityStatus != "" {
				auditArtifact(t, root, vector.AuthorityStatus)
			}
			for _, reference := range vector.Predecessors {
				auditArtifact(t, root, reference)
			}
			var stdout, stderr bytes.Buffer
			exit := Main(vectorArguments(root, vector), &stdout, &stderr)
			wantExit := 1
			wantOK := false
			if vector.ExpectedCode == "OK" {
				wantExit, wantOK = 0, true
			}
			want := output{
				CertificateDigest: expectedDigest(t, root, vector),
				Code:              vector.ExpectedCode,
				Mode:              vector.Mode,
				OK:                wantOK,
				ProtocolVersion:   protocolVersion,
			}
			encoded, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			if exit != wantExit {
				t.Fatalf("exit = %d, want %d; stderr=%q", exit, wantExit, stderr.String())
			}
			if stdout.String() != string(encoded)+"\n" {
				t.Fatalf("stdout = %q, want %q", stdout.String(), string(encoded)+"\n")
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestCLIRejectsEveryModeInapplicableFlag(t *testing.T) {
	root, manifest := loadManifest(t)
	historical := vectorNamed(t, manifest, "valid-historical")
	causal := vectorNamed(t, manifest, "valid-causal-chain")
	current := vectorNamed(t, manifest, "valid-current")
	var predecessor string
	for digest, reference := range causal.Predecessors {
		predecessor = digest + "=" + artifactPath(root, reference)
		break
	}
	currentFlags := [][2]string{
		{"--authority-status", artifactPath(root, current.AuthorityStatus)},
		{"--request-nonce", current.CurrentInputs.RequestNonce},
		{"--now-ms", current.CurrentInputs.NowMS},
		{"--highest-trust-log-sequence", current.CurrentInputs.HighestTrustLogSequence},
		{"--highest-trust-log-head", current.CurrentInputs.HighestTrustLogHead},
		{"--maximum-staleness-ms", current.CurrentInputs.MaximumStalenessMS},
	}
	causalFlags := [][2]string{
		{"--predecessor", predecessor},
		{"--max-depth", "64"},
		{"--max-certificates", "4096"},
		{"--max-total-bytes", "67108864"},
	}
	tests := make([]struct {
		name   string
		vector manifestVector
		flag   [2]string
	}, 0, len(currentFlags)*2+len(causalFlags)*2)
	for _, flag := range append(currentFlags, causalFlags...) {
		tests = append(tests, struct {
			name   string
			vector manifestVector
			flag   [2]string
		}{name: "historical-" + strings.TrimPrefix(flag[0], "--"), vector: historical, flag: flag})
	}
	for _, flag := range currentFlags {
		tests = append(tests, struct {
			name   string
			vector manifestVector
			flag   [2]string
		}{name: "causal-" + strings.TrimPrefix(flag[0], "--"), vector: causal, flag: flag})
	}
	for _, flag := range causalFlags {
		tests = append(tests, struct {
			name   string
			vector manifestVector
			flag   [2]string
		}{name: "current-" + strings.TrimPrefix(flag[0], "--"), vector: current, flag: flag})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := append(vectorArguments(root, test.vector), test.flag[0], test.flag[1])
			assertCLIError(t, test.vector.Mode, arguments)
		})
	}
}

func TestCLIRejectsDuplicatePredecessorDigest(t *testing.T) {
	root, manifest := loadManifest(t)
	vector := vectorNamed(t, manifest, "valid-causal-chain")
	arguments := vectorArguments(root, vector)
	for digest, reference := range vector.Predecessors {
		arguments = append(arguments, "--predecessor", digest+"="+artifactPath(root, reference))
		break
	}
	assertCLIError(t, "causal", arguments)
}

func TestCLIMisuseAndIOErrorsPrecedeProtocolRejection(t *testing.T) {
	root, manifest := loadManifest(t)
	invalidTrust := filepath.Join(t.TempDir(), "invalid-trust.json")
	if err := os.WriteFile(invalidTrust, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	causal := vectorNamed(t, manifest, "valid-causal-chain")
	duplicateArguments := replaceFlagValue(vectorArguments(root, causal), "--trust", invalidTrust)
	for digest, reference := range causal.Predecessors {
		duplicateArguments = append(duplicateArguments, "--predecessor", digest+"="+artifactPath(root, reference))
		break
	}

	current := vectorNamed(t, manifest, "valid-current")
	missingRequired := replaceFlagValue(vectorArguments(root, current), "--trust", invalidTrust)
	missingRequired = removeFlag(missingRequired, "--maximum-staleness-ms")
	unreadableStatus := replaceFlagValue(vectorArguments(root, current), "--trust", invalidTrust)
	unreadableStatus = replaceFlagValue(unreadableStatus, "--authority-status", filepath.Join(t.TempDir(), "missing-status.json"))

	for _, test := range []struct {
		name      string
		mode      string
		arguments []string
	}{
		{name: "duplicate-predecessor-before-invalid-trust", mode: "causal", arguments: duplicateArguments},
		{name: "missing-required-before-invalid-trust", mode: "current", arguments: missingRequired},
		{name: "unreadable-status-before-invalid-trust", mode: "current", arguments: unreadableStatus},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertCLIError(t, test.mode, test.arguments)
		})
	}
}

func TestCausalCLIRejectsExcessUnusedPredecessorMappings(t *testing.T) {
	root, manifest := loadManifest(t)
	vector := causalLeafVector(t, manifest)
	arguments := append(
		vectorArguments(root, vector),
		"--predecessor", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="+artifactPath(root, vector.Certificate),
		"--max-certificates", "1",
	)
	assertProtocolError(t, "causal", "SIZE_LIMIT_EXCEEDED", arguments)
}

func TestCausalCLIRejectsOversizedUnusedPredecessorFile(t *testing.T) {
	root, manifest := loadManifest(t)
	vector := causalLeafVector(t, manifest)
	oversized := filepath.Join(t.TempDir(), "oversized-predecessor.json")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	maximum := len(auditArtifact(t, root, vector.Certificate)) + 8
	arguments := append(
		vectorArguments(root, vector),
		"--predecessor", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="+oversized,
		"--max-certificates", "2",
		"--max-total-bytes", strconv.Itoa(maximum),
	)
	assertProtocolError(t, "causal", "SIZE_LIMIT_EXCEEDED", arguments)
}

func TestCLIRejectsOversizedPrimaryInputsWithoutUnboundedReads(t *testing.T) {
	root, manifest := loadManifest(t)
	historical := vectorNamed(t, manifest, "valid-historical")
	causal := vectorNamed(t, manifest, "valid-causal-chain")
	current := vectorNamed(t, manifest, "valid-current")
	tests := []struct {
		name    string
		vector  manifestVector
		flag    string
		maximum int
	}{
		{name: "historical-certificate", vector: historical, flag: "--certificate", maximum: cj1.MaxEnvelopeBytes},
		{name: "historical-trust", vector: historical, flag: "--trust", maximum: cj1.MaxPayloadBytes},
		{name: "causal-certificate", vector: causal, flag: "--certificate", maximum: cj1.MaxEnvelopeBytes},
		{name: "causal-trust", vector: causal, flag: "--trust", maximum: cj1.MaxPayloadBytes},
		{name: "current-certificate", vector: current, flag: "--certificate", maximum: cj1.MaxEnvelopeBytes},
		{name: "current-trust", vector: current, flag: "--trust", maximum: cj1.MaxPayloadBytes},
		{name: "current-authority-status", vector: current, flag: "--authority-status", maximum: cj1.MaxPayloadBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oversized := filepath.Join(t.TempDir(), "oversized.json")
			if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), test.maximum+1), 0o600); err != nil {
				t.Fatal(err)
			}
			arguments := replaceFlagValue(vectorArguments(root, test.vector), test.flag, oversized)
			assertProtocolError(t, test.vector.Mode, "SIZE_LIMIT_EXCEEDED", arguments)
		})
	}
}

func TestCLIPrimaryInputReadFailuresRemainCLIErrorsInEveryMode(t *testing.T) {
	root, manifest := loadManifest(t)
	historical := vectorNamed(t, manifest, "valid-historical")
	causal := vectorNamed(t, manifest, "valid-causal-chain")
	current := vectorNamed(t, manifest, "valid-current")
	tests := []struct {
		name   string
		vector manifestVector
		flag   string
	}{
		{name: "historical-certificate", vector: historical, flag: "--certificate"},
		{name: "historical-trust", vector: historical, flag: "--trust"},
		{name: "causal-certificate", vector: causal, flag: "--certificate"},
		{name: "causal-trust", vector: causal, flag: "--trust"},
		{name: "current-certificate", vector: current, flag: "--certificate"},
		{name: "current-trust", vector: current, flag: "--trust"},
		{name: "current-authority-status", vector: current, flag: "--authority-status"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			missing := filepath.Join(t.TempDir(), "missing.json")
			arguments := replaceFlagValue(vectorArguments(root, test.vector), test.flag, missing)
			assertCLIError(t, test.vector.Mode, arguments)
		})
	}
}

func TestCLIPrimaryInputReadLimitsAreInclusive(t *testing.T) {
	root, manifest := loadManifest(t)
	historical := vectorNamed(t, manifest, "valid-historical")
	current := vectorNamed(t, manifest, "valid-current")
	tests := []struct {
		name    string
		vector  manifestVector
		flag    string
		maximum int
	}{
		{name: "certificate", vector: historical, flag: "--certificate", maximum: cj1.MaxEnvelopeBytes},
		{name: "trust", vector: historical, flag: "--trust", maximum: cj1.MaxPayloadBytes},
		{name: "authority-status", vector: current, flag: "--authority-status", maximum: cj1.MaxPayloadBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boundary := filepath.Join(t.TempDir(), "boundary.json")
			if err := os.WriteFile(boundary, bytes.Repeat([]byte("x"), test.maximum), 0o600); err != nil {
				t.Fatal(err)
			}
			arguments := replaceFlagValue(vectorArguments(root, test.vector), test.flag, boundary)
			assertProtocolError(t, test.vector.Mode, "MALFORMED_JSON", arguments)
		})
	}
}

func TestCLIStopsReadingPrimaryInputsAtLimitPlusOne(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("streaming path test requires /proc/self/fd")
	}
	root, manifest := loadManifest(t)
	historical := vectorNamed(t, manifest, "valid-historical")
	current := vectorNamed(t, manifest, "valid-current")
	tests := []struct {
		name    string
		vector  manifestVector
		flag    string
		maximum int
	}{
		{name: "certificate", vector: historical, flag: "--certificate", maximum: cj1.MaxEnvelopeBytes},
		{name: "trust", vector: historical, flag: "--trust", maximum: cj1.MaxPayloadBytes},
		{name: "authority-status", vector: current, flag: "--authority-status", maximum: cj1.MaxPayloadBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close() }()
			path := fmt.Sprintf("/proc/self/fd/%d", reader.Fd())
			releaseWriter := make(chan struct{})
			writerDone := make(chan error, 1)
			go func() {
				_, err := writer.Write(bytes.Repeat([]byte("x"), test.maximum+1))
				writerDone <- err
				<-releaseWriter
				_ = writer.Close()
			}()

			arguments := replaceFlagValue(vectorArguments(root, test.vector), test.flag, path)
			completed := make(chan struct {
				exit   int
				stdout string
			}, 1)
			go func() {
				var stdout bytes.Buffer
				exit := Main(arguments, &stdout, io.Discard)
				completed <- struct {
					exit   int
					stdout string
				}{exit: exit, stdout: stdout.String()}
			}()

			select {
			case result := <-completed:
				close(releaseWriter)
				if err := <-writerDone; err != nil {
					t.Fatal(err)
				}
				want, err := json.Marshal(output{Code: "SIZE_LIMIT_EXCEEDED", Mode: test.vector.Mode, ProtocolVersion: protocolVersion})
				if err != nil {
					t.Fatal(err)
				}
				if result.exit != 1 || result.stdout != string(want)+"\n" {
					t.Fatalf("result = exit %d, stdout %q; want exit 1, stdout %q", result.exit, result.stdout, string(want)+"\n")
				}
			case <-time.After(5 * time.Second):
				close(releaseWriter)
				if err := <-writerDone; err != nil {
					t.Fatal(err)
				}
				<-completed
				t.Fatal("primary input reader waited for EOF after limit+1 bytes")
			}
		})
	}
}

func replaceFlagValue(arguments []string, name, value string) []string {
	result := append([]string(nil), arguments...)
	for index := 0; index+1 < len(result); index++ {
		if result[index] == name {
			result[index+1] = value
			return result
		}
	}
	panic("flag not found: " + name)
}

func removeFlag(arguments []string, name string) []string {
	result := make([]string, 0, len(arguments)-2)
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == name {
			index++
			continue
		}
		result = append(result, arguments[index])
	}
	return result
}

func TestCLIParseErrorsEmitOnlyCompactJSON(t *testing.T) {
	root, manifest := loadManifest(t)
	vector := vectorNamed(t, manifest, "valid-historical")
	for _, extra := range [][]string{{"--unknown", "x"}, {"--max-depth", "not-an-integer"}} {
		arguments := append(vectorArguments(root, vector), extra...)
		assertCLIError(t, "historical", arguments)
	}
}

func assertCLIError(t testing.TB, mode string, arguments []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := Main(arguments, &stdout, &stderr)
	want := output{Code: "CLI_ERROR", Mode: mode, ProtocolVersion: protocolVersion}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if exit != 2 {
		t.Fatalf("exit = %d, want 2; stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	if stdout.String() != string(encoded)+"\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), string(encoded)+"\n")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func assertProtocolError(t testing.TB, mode, code string, arguments []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := Main(arguments, &stdout, &stderr)
	want := output{Code: code, Mode: mode, ProtocolVersion: protocolVersion}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if exit != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	if stdout.String() != string(encoded)+"\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), string(encoded)+"\n")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestCLIWriteFailureReturnsTwo(t *testing.T) {
	root, manifest := loadManifest(t)
	vector := vectorNamed(t, manifest, "valid-historical")
	var stderr bytes.Buffer
	if exit := Main(vectorArguments(root, vector), failingWriter{}, &stderr); exit != 2 {
		t.Fatalf("exit = %d, want 2", exit)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}
