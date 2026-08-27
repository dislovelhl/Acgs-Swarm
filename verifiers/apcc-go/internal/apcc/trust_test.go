package apcc

import "testing"

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
}

func FuzzPublicVerificationAPIsNeverPanic(f *testing.F) {
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, envelope, status []byte) {
		_ = VerifyHistorical(envelope, nil)
		_ = VerifyCurrent(envelope, nil, CurrentInputs{AuthorityStatus: status})
	})
}
