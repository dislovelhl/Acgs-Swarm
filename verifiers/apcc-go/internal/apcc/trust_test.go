package apcc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type fixtureInputs struct {
	RequestNonce            string `json:"request_nonce"`
	NowMS                   string `json:"now_ms"`
	HighestTrustLogSequence string `json:"highest_trust_log_sequence"`
	HighestTrustLogHead     string `json:"highest_trust_log_head"`
	MaximumStalenessMS      string `json:"maximum_staleness_ms"`
}

type fixtureVector struct {
	Name            string            `json:"name"`
	Certificate     string            `json:"certificate"`
	Trust           string            `json:"trust"`
	AuthorityStatus string            `json:"authority_status"`
	CurrentInputs   fixtureInputs     `json:"current_inputs"`
	Predecessors    map[string]string `json:"predecessors"`
}

type fixtureManifest struct {
	Vectors []fixtureVector `json:"vectors"`
}

func fixtureRoot(t testing.TB) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate APCC Go test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "tests", "fixtures", "apcc", "v1"))
}

func fixtureBytes(t testing.TB, root, reference string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(reference)))
	if err != nil {
		t.Fatalf("read fixture %q: %v", reference, err)
	}
	return raw
}

func loadFixtureVector(t testing.TB, name string) (string, fixtureVector) {
	t.Helper()
	root := fixtureRoot(t)
	var manifest fixtureManifest
	if err := json.Unmarshal(fixtureBytes(t, root, "manifest.json"), &manifest); err != nil {
		t.Fatalf("decode fixture manifest: %v", err)
	}
	for _, vector := range manifest.Vectors {
		if vector.Name == name {
			return root, vector
		}
	}
	t.Fatalf("fixture vector %q not found", name)
	return "", fixtureVector{}
}

func fixtureTrust(t testing.TB, root string, vector fixtureVector) *Trust {
	t.Helper()
	trust, code := ParseTrust(fixtureBytes(t, root, vector.Trust))
	if code != "" {
		t.Fatalf("parse fixture trust: %s", code)
	}
	return trust
}

type testResolver struct {
	values map[string][]byte
	err    error
	panic  bool
}

func (resolver testResolver) ResolvePredecessor(digest string) ([]byte, bool, error) {
	if resolver.panic {
		panic("hostile predecessor resolver")
	}
	if resolver.err != nil {
		return nil, false, resolver.err
	}
	value, ok := resolver.values[digest]
	return value, ok, nil
}

func TestTrustRejectsCrossRoleKeyMaterialReuse(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"bindings":[{"key_id":"producer-key","public_key_b64u":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","role":"producer","scope":["agent-1","authority:ns:execute","root"]},{"key_id":"policy-key","public_key_b64u":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","role":"policy","scope":["policy-1","1","1"]}],"protocol_version":"APCC-1.0-draft"}`)
	if _, code := ParseTrust(raw); code != "UNKNOWN_KEY" {
		t.Fatalf("got %q, want UNKNOWN_KEY", code)
	}
}

func TestTrustRequiresExactRoleScope(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"bindings":[{"key_id":"commit-key","public_key_b64u":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","role":"commit","scope":["store-1","extra"]}],"protocol_version":"APCC-1.0-draft"}`)
	if _, code := ParseTrust(raw); code != "UNKNOWN_KEY" {
		t.Fatalf("got %q, want UNKNOWN_KEY", code)
	}
}

func TestPublicVerificationAPIsFailClosedWithNilTrust(t *testing.T) {
	t.Parallel()
	if result := VerifyHistorical([]byte(`{}`), nil); result.OK || result.Code != "UNKNOWN_KEY" {
		t.Fatalf("VerifyHistorical nil trust = %+v, want UNKNOWN_KEY", result)
	}
	if result := VerifyCurrent([]byte(`{}`), nil, CurrentInputs{}); result.OK || result.Code != "UNKNOWN_KEY" {
		t.Fatalf("VerifyCurrent nil trust = %+v, want UNKNOWN_KEY", result)
	}
	if result := VerifyCausalClosure([]byte(`{}`), nil, nil, DefaultCausalClosureLimits()); result.OK || result.Code != "UNKNOWN_KEY" {
		t.Fatalf("VerifyCausalClosure nil trust = %+v, want UNKNOWN_KEY", result)
	}
}

func TestValidSeededPublicVerificationAPIsReachSuccessPaths(t *testing.T) {
	historicalRoot, historical := loadFixtureVector(t, "valid-historical")
	trust := fixtureTrust(t, historicalRoot, historical)
	if result := VerifyHistorical(fixtureBytes(t, historicalRoot, historical.Certificate), trust); !result.OK {
		t.Fatalf("VerifyHistorical valid seed = %+v", result)
	}

	currentRoot, current := loadFixtureVector(t, "valid-current")
	currentResult := VerifyCurrent(
		fixtureBytes(t, currentRoot, current.Certificate),
		trust,
		CurrentInputs{
			AuthorityStatus:         fixtureBytes(t, currentRoot, current.AuthorityStatus),
			RequestNonce:            current.CurrentInputs.RequestNonce,
			NowMS:                   current.CurrentInputs.NowMS,
			HighestTrustLogSequence: current.CurrentInputs.HighestTrustLogSequence,
			HighestTrustLogHead:     current.CurrentInputs.HighestTrustLogHead,
			MaximumStalenessMS:      current.CurrentInputs.MaximumStalenessMS,
		},
	)
	if !currentResult.OK {
		t.Fatalf("VerifyCurrent valid seed = %+v", currentResult)
	}

	causalRoot, causal := loadFixtureVector(t, "valid-causal-chain")
	values := make(map[string][]byte, len(causal.Predecessors))
	for digest, reference := range causal.Predecessors {
		values[digest] = fixtureBytes(t, causalRoot, reference)
	}
	causalResult := VerifyCausalClosure(
		fixtureBytes(t, causalRoot, causal.Certificate),
		trust,
		testResolver{values: values},
		DefaultCausalClosureLimits(),
	)
	if !causalResult.OK {
		t.Fatalf("VerifyCausalClosure valid seed = %+v", causalResult)
	}
}

func TestCausalResolverErrorsAndPanicsFailClosed(t *testing.T) {
	root, vector := loadFixtureVector(t, "valid-causal-chain")
	envelope := fixtureBytes(t, root, vector.Certificate)
	trust := fixtureTrust(t, root, vector)
	for _, resolver := range []PredecessorResolver{
		nil,
		testResolver{err: errors.New("resolver unavailable")},
		testResolver{panic: true},
	} {
		result := VerifyCausalClosure(envelope, trust, resolver, DefaultCausalClosureLimits())
		if result.OK || result.Code != "INVALID_PREDECESSOR" {
			t.Fatalf("hostile resolver result = %+v, want INVALID_PREDECESSOR", result)
		}
	}
}

func TestFoundInvalidPredecessorsCollapseToInvalidPredecessor(t *testing.T) {
	root, vector := loadFixtureVector(t, "valid-causal-chain")
	envelope := fixtureBytes(t, root, vector.Certificate)
	trust := fixtureTrust(t, root, vector)
	var digest, reference string
	for digest, reference = range vector.Predecessors {
		break
	}
	invalidSeal := fixtureBytes(t, root, reference)
	var outer map[string]any
	if err := json.Unmarshal(invalidSeal, &outer); err != nil {
		t.Fatalf("decode valid predecessor: %v", err)
	}
	seal, ok := outer["seal"].(map[string]any)
	if !ok {
		t.Fatal("valid predecessor lacks seal")
	}
	signature, ok := seal["signature_b64u"].(string)
	if !ok || signature == "" {
		t.Fatal("valid predecessor lacks signature")
	}
	if signature[0] == 'A' {
		seal["signature_b64u"] = "B" + signature[1:]
	} else {
		seal["signature_b64u"] = "A" + signature[1:]
	}
	invalidSeal, err := json.Marshal(outer)
	if err != nil {
		t.Fatalf("encode invalid-signature predecessor: %v", err)
	}

	for _, test := range []struct {
		name           string
		resolved       []byte
		historicalCode string
	}{
		{name: "malformed", resolved: []byte(`{}`), historicalCode: "MISSING_FIELD"},
		{name: "invalid-seal", resolved: invalidSeal, historicalCode: "INVALID_COMMIT_SEAL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			historical := VerifyHistorical(test.resolved, trust)
			if historical.OK || historical.Code != test.historicalCode {
				t.Fatalf("root historical result = %+v, want %s", historical, test.historicalCode)
			}
			result := VerifyCausalClosure(envelope, trust, testResolver{
				values: map[string][]byte{digest: test.resolved},
			}, DefaultCausalClosureLimits())
			if result.OK || result.Code != "INVALID_PREDECESSOR" {
				t.Fatalf("causal result = %+v, want INVALID_PREDECESSOR", result)
			}
		})
	}
}

func TestInvalidCausalLimitsFailClosed(t *testing.T) {
	root, vector := loadFixtureVector(t, "valid-causal-chain")
	envelope := fixtureBytes(t, root, vector.Certificate)
	trust := fixtureTrust(t, root, vector)
	resolver := testResolver{values: map[string][]byte{}}
	for _, limits := range []CausalClosureLimits{
		{MaxDepth: -1, MaxCertificates: 1, MaxTotalBytes: 1},
		{MaxDepth: 1, MaxCertificates: 0, MaxTotalBytes: 1},
		{MaxDepth: 1, MaxCertificates: 1, MaxTotalBytes: 0},
	} {
		result := VerifyCausalClosure(envelope, trust, resolver, limits)
		if result.OK || result.Code != "SIZE_LIMIT_EXCEEDED" {
			t.Fatalf("invalid limits result = %+v, want SIZE_LIMIT_EXCEEDED", result)
		}
	}
}

func FuzzPublicVerificationAPIsNeverPanic(f *testing.F) {
	historicalRoot, historical := loadFixtureVector(f, "valid-historical")
	currentRoot, current := loadFixtureVector(f, "valid-current")
	causalRoot, causal := loadFixtureVector(f, "valid-causal-chain")
	trust := fixtureTrust(f, historicalRoot, historical)
	historicalEnvelope := fixtureBytes(f, historicalRoot, historical.Certificate)
	currentEnvelope := fixtureBytes(f, currentRoot, current.Certificate)
	currentStatus := fixtureBytes(f, currentRoot, current.AuthorityStatus)
	causalEnvelope := fixtureBytes(f, causalRoot, causal.Certificate)
	var predecessorDigest, predecessorReference string
	for predecessorDigest, predecessorReference = range causal.Predecessors {
		break
	}
	predecessor := fixtureBytes(f, causalRoot, predecessorReference)
	f.Add(historicalEnvelope, currentStatus, predecessor)
	f.Fuzz(func(t *testing.T, envelope, status, resolved []byte) {
		_ = VerifyHistorical(envelope, trust)
		_ = VerifyCurrent(currentEnvelope, trust, CurrentInputs{
			AuthorityStatus:         status,
			RequestNonce:            current.CurrentInputs.RequestNonce,
			NowMS:                   current.CurrentInputs.NowMS,
			HighestTrustLogSequence: current.CurrentInputs.HighestTrustLogSequence,
			HighestTrustLogHead:     current.CurrentInputs.HighestTrustLogHead,
			MaximumStalenessMS:      current.CurrentInputs.MaximumStalenessMS,
		})
		_ = VerifyCausalClosure(causalEnvelope, trust, testResolver{
			values: map[string][]byte{predecessorDigest: resolved},
		}, DefaultCausalClosureLimits())
		_ = VerifyCausalClosure(causalEnvelope, trust, testResolver{
			err: errors.New("resolver unavailable"),
		}, DefaultCausalClosureLimits())
		_ = VerifyCausalClosure(causalEnvelope, trust, testResolver{
			panic: true,
		}, DefaultCausalClosureLimits())
	})
}
