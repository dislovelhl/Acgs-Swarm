package apcc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/acgs/apcc-go-verifier/internal/cj1"
)

const maxPredecessors = 4096

var (
	decimalPattern    = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	authorityPattern  = regexp.MustCompile(`^authority:[A-Za-z0-9][A-Za-z0-9._/-]{0,63}:[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`)
	b64uPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
)

type schemaKind uint8

const (
	stringKind schemaKind = iota
	objectKind
	arrayKind
)

type schema struct {
	kind   schemaKind
	fields map[string]*schema
	item   *schema
}

func stringsOnly(names ...string) *schema {
	fields := make(map[string]*schema, len(names))
	for _, name := range names {
		fields[name] = &schema{kind: stringKind}
	}
	return &schema{kind: objectKind, fields: fields}
}

var (
	signatureSchema   = stringsOnly("algorithm", "key_id", "signature_b64u")
	predecessorSchema = stringsOnly("workflow_id", "node_id", "committed_node_version", "commit_id", "certificate_digest", "output_digest")
	certificateSchema = &schema{kind: objectKind, fields: map[string]*schema{
		"header":  stringsOnly("protocol_version", "certificate_type", "encoding_profile", "digest_algorithm", "signature_algorithm", "authority_store_id", "commit_authority_key_id", "certificate_sequence"),
		"subject": stringsOnly("workflow_id", "node_id", "attempt_id", "agent_id", "actor_authority", "input_digest", "output_digest"),
		"context": stringsOnly("policy_id", "policy_version", "policy_epoch", "authority_root", "authority_epoch", "agent_revocation_generation", "workflow_revocation_generation", "workflow_epoch"),
		"evidence": {kind: objectKind, fields: map[string]*schema{
			"producer_statement":         stringsOnly("protocol_version", "statement_type", "producer_key_id", "workflow_id", "node_id", "attempt_id", "agent_id", "actor_authority", "input_digest", "output_digest", "predecessor_root", "expected_node_version", "commit_id", "nonce", "issued_at_ms", "expires_at_ms"),
			"producer_statement_digest":  {kind: stringKind},
			"policy_statement":           stringsOnly("protocol_version", "statement_type", "policy_key_id", "proposal_digest", "decision", "policy_id", "policy_version", "policy_epoch", "workflow_id", "node_id", "attempt_id", "issued_at_ms", "expires_at_ms"),
			"policy_statement_digest":    {kind: stringKind},
			"authority_statement":        stringsOnly("protocol_version", "statement_type", "authority_key_id", "proposal_digest", "agent_id", "producer_key_id", "actor_authority", "authority_root", "authority_epoch", "agent_revocation_generation", "workflow_revocation_generation", "workflow_epoch", "workflow_id", "node_id", "attempt_id", "issued_at_ms", "expires_at_ms"),
			"authority_statement_digest": {kind: stringKind},
		}},
		"decision": stringsOnly("outcome", "reason", "commit_id", "nonce", "committed_at_ms"),
		"bindings": {kind: objectKind, fields: map[string]*schema{
			"expected_node_version": {kind: stringKind}, "committed_node_version": {kind: stringKind}, "predecessor_root": {kind: stringKind},
			"predecessors": {kind: arrayKind, item: predecessorSchema},
		}},
		"signatures": {kind: objectKind, fields: map[string]*schema{"producer": signatureSchema, "policy_authority": signatureSchema, "authority_registry": signatureSchema}},
	}}
	envelopeSchema = &schema{kind: objectKind, fields: map[string]*schema{
		"envelope_type": {kind: stringKind}, "payload_b64u": {kind: stringKind}, "payload_sha256": {kind: stringKind}, "seal": signatureSchema,
	}}
	statusSchema = &schema{kind: objectKind, fields: map[string]*schema{
		"body":      stringsOnly("protocol_version", "statement_type", "authority_store_id", "status_key_id", "request_nonce", "certificate_digest", "certificate_sequence", "trust_log_sequence", "trust_log_head", "status", "actor_revocation_generation", "workflow_revocation_generation", "superseded", "this_update_ms", "next_update_ms"),
		"signature": signatureSchema,
	}}
)

var decimalNames = setOf("certificate_sequence", "policy_version", "policy_epoch", "authority_epoch", "agent_revocation_generation", "actor_revocation_generation", "workflow_revocation_generation", "workflow_epoch", "expected_node_version", "committed_node_version", "issued_at_ms", "expires_at_ms", "committed_at_ms", "trust_log_sequence", "this_update_ms", "next_update_ms")
var digestNames = setOf("input_digest", "output_digest", "authority_root", "producer_statement_digest", "policy_statement_digest", "authority_statement_digest", "proposal_digest", "predecessor_root", "certificate_digest", "payload_sha256", "trust_log_head")
var identifierNames = setOf("authority_store_id", "commit_authority_key_id", "workflow_id", "node_id", "attempt_id", "agent_id", "policy_id", "commit_id", "producer_key_id", "policy_key_id", "authority_key_id", "status_key_id", "key_id")

func setOf(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validateSchema(value cj1.Value, expected *schema) string {
	switch expected.kind {
	case stringKind:
		if _, ok := value.(string); !ok {
			return "WRONG_JSON_TYPE"
		}
	case objectKind:
		object, ok := value.(cj1.Object)
		if !ok {
			return "WRONG_JSON_TYPE"
		}
		if code := validateKeys(object, expected.fields); code != "" {
			return code
		}
		for _, name := range sortedKeys(expected.fields) {
			child := expected.fields[name]
			if code := validateSchema(object[name], child); code != "" {
				return code
			}
		}
	case arrayKind:
		items, ok := value.(cj1.Array)
		if !ok {
			return "WRONG_JSON_TYPE"
		}
		if len(items) > maxPredecessors {
			return "SIZE_LIMIT_EXCEEDED"
		}
		for _, item := range items {
			if code := validateSchema(item, expected.item); code != "" {
				return code
			}
		}
	}
	return ""
}

func validateKeys(object cj1.Object, expected map[string]*schema) string {
	extra := make([]string, 0)
	for key := range object {
		if _, ok := expected[key]; !ok {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	for _, key := range extra {
		for wanted := range expected {
			if strings.EqualFold(key, wanted) {
				return "CASE_MISMATCHED_FIELD"
			}
		}
	}
	if len(extra) > 0 {
		return "UNKNOWN_FIELD"
	}
	missing := make([]string, 0)
	for key := range expected {
		if _, ok := object[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return "MISSING_FIELD"
	}
	return ""
}

func validateScalars(value cj1.Value, name string) string {
	switch item := value.(type) {
	case cj1.Object:
		for _, key := range sortedKeys(item) {
			child := item[key]
			if code := validateScalars(child, key); code != "" {
				return code
			}
		}
	case cj1.Array:
		for _, child := range item {
			if code := validateScalars(child, name); code != "" {
				return code
			}
		}
	case string:
		if _, ok := decimalNames[name]; ok {
			if _, valid := decimal(item); !valid {
				return "INVALID_DECIMAL_STRING"
			}
		} else if _, ok := digestNames[name]; ok {
			if _, valid := decodeB64u(item, 32); !valid {
				return "INVALID_BASE64URL"
			}
		} else if name == "nonce" || name == "request_nonce" {
			if _, valid := decodeB64u(item, 16); !valid {
				return "INVALID_BASE64URL"
			}
		} else if name == "signature_b64u" {
			if _, valid := decodeB64u(item, 64); !valid {
				return "INVALID_BASE64URL"
			}
		} else if name == "payload_b64u" {
			if _, valid := decodeB64u(item, -1); !valid {
				return "INVALID_BASE64URL"
			}
		} else if name == "actor_authority" && !authorityPattern.MatchString(item) {
			return "NONCANONICAL_ENCODING"
		} else if _, ok := identifierNames[name]; ok && !identifierPattern.MatchString(item) {
			return "NONCANONICAL_ENCODING"
		}
	default:
		return "WRONG_JSON_TYPE"
	}
	return ""
}

func decimal(value string) (uint64, bool) {
	if !decimalPattern.MatchString(value) {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil && parsed <= 9007199254740991
}

func decodeB64u(value string, expected int) ([]byte, bool) {
	if strings.Contains(value, "=") || !b64uPattern.MatchString(value) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || (expected >= 0 && len(decoded) != expected) {
		return nil, false
	}
	return decoded, true
}

func digest(raw []byte) string {
	value := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func object(value cj1.Value) (cj1.Object, bool)  { result, ok := value.(cj1.Object); return result, ok }
func array(value cj1.Value) (cj1.Array, bool)    { result, ok := value.(cj1.Array); return result, ok }
func text(object cj1.Object, name string) string { value, _ := object[name].(string); return value }

func child(parent cj1.Object, name string) cj1.Object {
	value, _ := object(parent[name])
	return value
}

func literal(value, expected, code string) string {
	if value != expected {
		return code
	}
	return ""
}

func canonical(value cj1.Value) []byte {
	encoded, _ := cj1.Encode(value)
	return encoded
}

func predecessorChecks(certificate cj1.Object) string {
	bindings := child(certificate, "bindings")
	items, _ := array(bindings["predecessors"])
	canonicalItems := make([][]byte, len(items))
	seenMembers, seenNodes, seenDigests := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for index, item := range items {
		entry, _ := object(item)
		member := canonical(entry)
		canonicalItems[index] = member
		key := string(member)
		node, certDigest := text(entry, "node_id"), text(entry, "certificate_digest")
		if _, ok := seenMembers[key]; ok {
			return "DUPLICATE_SET_MEMBER"
		}
		if _, ok := seenNodes[node]; ok {
			return "DUPLICATE_SET_MEMBER"
		}
		if _, ok := seenDigests[certDigest]; ok {
			return "DUPLICATE_SET_MEMBER"
		}
		seenMembers[key], seenNodes[node], seenDigests[certDigest] = struct{}{}, struct{}{}, struct{}{}
	}
	if !sort.SliceIsSorted(canonicalItems, func(i, j int) bool { return bytes.Compare(canonicalItems[i], canonicalItems[j]) < 0 }) {
		return "NONCANONICAL_ENCODING"
	}
	return ""
}
