package apcc

import (
	"bytes"

	"github.com/acgs/apcc-go-verifier/internal/cj1"
)

type TrustBinding struct {
	Role      string
	Scope     []string
	KeyID     string
	PublicKey []byte
}

type Trust struct {
	bindings map[string]TrustBinding
}

var scopeLengths = map[string]int{"producer": 3, "policy": 3, "registry": 2, "commit": 1, "status": 1}

var trustSchema = &schema{kind: objectKind, fields: map[string]*schema{
	"protocol_version": {kind: stringKind},
	"bindings": {kind: arrayKind, item: &schema{kind: objectKind, fields: map[string]*schema{
		"role": {kind: stringKind}, "scope": {kind: arrayKind, item: &schema{kind: stringKind}}, "key_id": {kind: stringKind}, "public_key_b64u": {kind: stringKind},
	}}},
}}

func ParseTrust(raw []byte) (*Trust, string) {
	value, parseErr := cj1.Parse(raw, cj1.MaxPayloadBytes)
	if parseErr != nil {
		return nil, parseErr.Code
	}
	if code := validateSchema(value, trustSchema); code != "" {
		return nil, code
	}
	root, _ := object(value)
	if text(root, "protocol_version") != "APCC-1.0-draft" {
		return nil, "UNKNOWN_PROTOCOL_VERSION"
	}
	items, _ := array(root["bindings"])
	trust := &Trust{bindings: map[string]TrustBinding{}}
	keyRoles, materialRoles := map[string]string{}, map[string]string{}
	for _, value := range items {
		item, _ := object(value)
		role := text(item, "role")
		expectedLength, known := scopeLengths[role]
		if !known {
			return nil, "UNKNOWN_KEY"
		}
		scopeValues, _ := array(item["scope"])
		if len(scopeValues) != expectedLength {
			return nil, "UNKNOWN_KEY"
		}
		scope := make([]string, len(scopeValues))
		for index, rawScope := range scopeValues {
			scope[index], _ = rawScope.(string)
			if scope[index] == "" {
				return nil, "UNKNOWN_KEY"
			}
		}
		keyID := text(item, "key_id")
		if !identifierPattern.MatchString(keyID) {
			return nil, "NONCANONICAL_ENCODING"
		}
		publicKey, valid := decodeB64u(text(item, "public_key_b64u"), 32)
		if !valid {
			return nil, "INVALID_BASE64URL"
		}
		identity := trustKey(role, scope)
		if _, duplicate := trust.bindings[identity]; duplicate {
			return nil, "UNKNOWN_KEY"
		}
		if prior, exists := keyRoles[keyID]; exists && prior != role {
			return nil, "UNKNOWN_KEY"
		}
		material := string(publicKey)
		if prior, exists := materialRoles[material]; exists && prior != role {
			return nil, "UNKNOWN_KEY"
		}
		trust.bindings[identity] = TrustBinding{Role: role, Scope: scope, KeyID: keyID, PublicKey: bytes.Clone(publicKey)}
		keyRoles[keyID], materialRoles[material] = role, role
	}
	return trust, ""
}

func trustKey(role string, scope []string) string {
	result := role
	for _, item := range scope {
		result += "\x00" + item
	}
	return result
}

func (trust *Trust) Resolve(role string, scope []string, keyID string) ([]byte, string) {
	if trust == nil {
		return nil, "UNKNOWN_KEY"
	}
	binding, ok := trust.bindings[trustKey(role, scope)]
	if !ok || binding.KeyID != keyID {
		return nil, "UNKNOWN_KEY"
	}
	return bytes.Clone(binding.PublicKey), ""
}
