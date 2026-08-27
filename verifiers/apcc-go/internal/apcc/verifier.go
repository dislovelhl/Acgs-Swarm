package apcc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"

	"github.com/acgs/apcc-go-verifier/internal/cj1"
)

const (
	proposalDomain  = "APCC-PROPOSAL-V1"
	policyDomain    = "APCC-POLICY-V1"
	authorityDomain = "APCC-AUTHORITY-V1"
	commitDomain    = "APCC-COMMIT-V1"
	statusDomain    = "APCC-AUTHORITY-STATUS-V1"
)

type Result struct {
	OK                bool
	Code              string
	CertificateDigest string
	Certificate       cj1.Object
}

type PredecessorResolver interface {
	ResolvePredecessor(certificateDigest string) ([]byte, bool, error)
}

type CausalClosureLimits struct {
	MaxDepth        int
	MaxCertificates int
	MaxTotalBytes   int
}

func DefaultCausalClosureLimits() CausalClosureLimits {
	return CausalClosureLimits{MaxDepth: 64, MaxCertificates: 4096, MaxTotalBytes: 64 * 1024 * 1024}
}

func failure(code string) Result { return Result{Code: code} }

func resolvePredecessor(resolver PredecessorResolver, digest string) (envelope []byte, found bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			envelope, found, err = nil, false, errors.New("predecessor resolver panic")
		}
	}()
	return resolver.ResolvePredecessor(digest)
}

type decodedCertificate struct {
	root    cj1.Object
	payload []byte
	digest  string
	seal    cj1.Object
}

func VerifyHistorical(envelope []byte, trust *Trust) Result {
	if trust == nil {
		return failure("UNKNOWN_KEY")
	}
	certificate, code := decodeEnvelope(envelope)
	if code != "" {
		return failure(code)
	}
	if digest(certificate.payload) != certificate.digest {
		return failure("INVALID_COMMIT_SEAL")
	}
	if code = verifyHeader(certificate.root); code != "" {
		return failure(code)
	}
	header := child(certificate.root, "header")
	if code = verifySignature(certificate.seal, text(header, "commit_authority_key_id"), trust, "commit", []string{text(header, "authority_store_id")}, commitDomain, certificate.payload, "INVALID_COMMIT_SEAL"); code != "" {
		return failure(code)
	}
	if code = verifyEvidence(certificate.root, trust); code != "" {
		return failure(code)
	}
	if code = verifyBindings(certificate.root); code != "" {
		return failure(code)
	}
	return Result{OK: true, Code: "OK", CertificateDigest: certificate.digest, Certificate: certificate.root}
}

func VerifyCausalClosure(envelope []byte, trust *Trust, resolver PredecessorResolver, limits CausalClosureLimits) Result {
	root := VerifyHistorical(envelope, trust)
	if !root.OK {
		return root
	}
	if resolver == nil {
		return failure("INVALID_PREDECESSOR")
	}
	if limits.MaxDepth < 0 || limits.MaxCertificates < 1 || limits.MaxTotalBytes < 1 {
		return failure("SIZE_LIMIT_EXCEEDED")
	}
	if len(envelope) > limits.MaxTotalBytes {
		return failure("SIZE_LIMIT_EXCEEDED")
	}
	cache := map[string]cj1.Object{root.CertificateDigest: root.Certificate}
	active := map[string]bool{root.CertificateDigest: true}
	complete := map[string]bool{}
	totalBytes := len(envelope)
	var visit func(cj1.Object, int) string
	visit = func(certificate cj1.Object, depth int) string {
		predecessors, _ := array(child(certificate, "bindings")["predecessors"])
		for _, value := range predecessors {
			reference, _ := object(value)
			claimedDigest := text(reference, "certificate_digest")
			if depth+1 > limits.MaxDepth {
				return "DEPTH_LIMIT_EXCEEDED"
			}
			if active[claimedDigest] {
				return "INVALID_PREDECESSOR"
			}
			resolved, found := cache[claimedDigest]
			if !found {
				if len(cache) >= limits.MaxCertificates {
					return "SIZE_LIMIT_EXCEEDED"
				}
				predecessorEnvelope, ok, resolveErr := resolvePredecessor(resolver, claimedDigest)
				if resolveErr != nil || !ok {
					return "INVALID_PREDECESSOR"
				}
				if totalBytes+len(predecessorEnvelope) > limits.MaxTotalBytes {
					return "SIZE_LIMIT_EXCEEDED"
				}
				historical := VerifyHistorical(predecessorEnvelope, trust)
				if !historical.OK {
					return "INVALID_PREDECESSOR"
				}
				if historical.CertificateDigest != claimedDigest {
					return "INVALID_PREDECESSOR"
				}
				resolved = historical.Certificate
				cache[claimedDigest] = resolved
				totalBytes += len(predecessorEnvelope)
			}
			if !predecessorReferenceMatches(reference, resolved, claimedDigest) {
				return "INVALID_PREDECESSOR"
			}
			if complete[claimedDigest] {
				continue
			}
			active[claimedDigest] = true
			if code := visit(resolved, depth+1); code != "" {
				return code
			}
			delete(active, claimedDigest)
			complete[claimedDigest] = true
		}
		return ""
	}
	if code := visit(root.Certificate, 0); code != "" {
		return failure(code)
	}
	return root
}

func predecessorReferenceMatches(reference, certificate cj1.Object, certificateDigest string) bool {
	subject := child(certificate, "subject")
	bindings := child(certificate, "bindings")
	decision := child(certificate, "decision")
	return text(reference, "workflow_id") == text(subject, "workflow_id") &&
		text(reference, "node_id") == text(subject, "node_id") &&
		text(reference, "committed_node_version") == text(bindings, "committed_node_version") &&
		text(reference, "commit_id") == text(decision, "commit_id") &&
		text(reference, "certificate_digest") == certificateDigest &&
		text(reference, "output_digest") == text(subject, "output_digest")
}

func decodeEnvelope(raw []byte) (decodedCertificate, string) {
	value, parseErr := cj1.Parse(raw, cj1.MaxEnvelopeBytes)
	if parseErr != nil {
		return decodedCertificate{}, parseErr.Code
	}
	if code := validateSchema(value, envelopeSchema); code != "" {
		return decodedCertificate{}, code
	}
	if code := validateScalars(value, ""); code != "" {
		return decodedCertificate{}, code
	}
	root, _ := object(value)
	if text(root, "envelope_type") != "apcc.detached-certificate-envelope" {
		return decodedCertificate{}, "UNSUPPORTED_CERTIFICATE_TYPE"
	}
	seal := child(root, "seal")
	if text(seal, "algorithm") != "Ed25519" {
		return decodedCertificate{}, "UNSUPPORTED_SIGNATURE_ALGORITHM"
	}
	payload, valid := decodeB64u(text(root, "payload_b64u"), -1)
	if !valid {
		return decodedCertificate{}, "INVALID_BASE64URL"
	}
	if len(payload) > cj1.MaxPayloadBytes {
		return decodedCertificate{}, "SIZE_LIMIT_EXCEEDED"
	}
	certificate, code := decodeCertificate(payload)
	if code != "" {
		return decodedCertificate{}, code
	}
	return decodedCertificate{root: certificate, payload: payload, digest: text(root, "payload_sha256"), seal: seal}, ""
}

func decodeCertificate(raw []byte) (cj1.Object, string) {
	value, parseErr := cj1.Parse(raw, cj1.MaxPayloadBytes)
	if parseErr != nil {
		return nil, parseErr.Code
	}
	if code := validateSchema(value, certificateSchema); code != "" {
		return nil, code
	}
	if code := validateScalars(value, ""); code != "" {
		return nil, code
	}
	root, _ := object(value)
	header := child(root, "header")
	for _, check := range [][3]string{{text(header, "protocol_version"), "APCC-1.0-draft", "UNKNOWN_PROTOCOL_VERSION"}, {text(header, "certificate_type"), "apcc.commit-certificate", "UNSUPPORTED_CERTIFICATE_TYPE"}, {text(header, "encoding_profile"), "APCC-CJ1", "UNSUPPORTED_ENCODING"}, {text(header, "digest_algorithm"), "SHA-256", "UNSUPPORTED_DIGEST_ALGORITHM"}, {text(header, "signature_algorithm"), "Ed25519", "UNSUPPORTED_SIGNATURE_ALGORITHM"}} {
		if code := literal(check[0], check[1], check[2]); code != "" {
			return nil, code
		}
	}
	evidence := child(root, "evidence")
	for _, check := range []struct{ name, statement string }{{"producer_statement", "apcc.producer-statement"}, {"policy_statement", "apcc.policy-statement"}, {"authority_statement", "apcc.authority-statement"}} {
		body := child(evidence, check.name)
		if text(body, "protocol_version") != "APCC-1.0-draft" {
			return nil, "UNKNOWN_PROTOCOL_VERSION"
		}
		if text(body, "statement_type") != check.statement {
			return nil, "UNSUPPORTED_STATEMENT_TYPE"
		}
	}
	if text(child(evidence, "policy_statement"), "decision") != "allow" {
		return nil, "SUBJECT_MISMATCH"
	}
	if text(child(root, "decision"), "outcome") != "committed" {
		return nil, "ILLEGAL_NODE_STATE"
	}
	bindings := child(root, "bindings")
	expected, _ := decimal(text(bindings, "expected_node_version"))
	committed, _ := decimal(text(bindings, "committed_node_version"))
	if committed != expected+1 {
		return nil, "NODE_VERSION_CONFLICT"
	}
	for _, name := range []string{"producer", "policy_authority", "authority_registry"} {
		if text(child(child(root, "signatures"), name), "algorithm") != "Ed25519" {
			return nil, "UNSUPPORTED_SIGNATURE_ALGORITHM"
		}
	}
	if code := predecessorChecks(root); code != "" {
		return nil, code
	}
	return root, ""
}

func verifyHeader(certificate cj1.Object) string {
	header := child(certificate, "header")
	checks := [][3]string{{text(header, "protocol_version"), "APCC-1.0-draft", "UNKNOWN_PROTOCOL_VERSION"}, {text(header, "certificate_type"), "apcc.commit-certificate", "UNSUPPORTED_CERTIFICATE_TYPE"}, {text(header, "encoding_profile"), "APCC-CJ1", "UNSUPPORTED_ENCODING"}, {text(header, "digest_algorithm"), "SHA-256", "UNSUPPORTED_DIGEST_ALGORITHM"}, {text(header, "signature_algorithm"), "Ed25519", "UNSUPPORTED_SIGNATURE_ALGORITHM"}}
	for _, check := range checks {
		if code := literal(check[0], check[1], check[2]); code != "" {
			return code
		}
	}
	if text(child(certificate, "decision"), "outcome") != "committed" {
		return "ILLEGAL_NODE_STATE"
	}
	return ""
}

func verifyEvidence(certificate cj1.Object, trust *Trust) string {
	evidence := child(certificate, "evidence")
	producer, policy, authority := child(evidence, "producer_statement"), child(evidence, "policy_statement"), child(evidence, "authority_statement")
	producerBytes, policyBytes, authorityBytes := canonical(producer), canonical(policy), canonical(authority)
	for _, check := range []struct {
		body    []byte
		claimed string
	}{{producerBytes, text(evidence, "producer_statement_digest")}, {policyBytes, text(evidence, "policy_statement_digest")}, {authorityBytes, text(evidence, "authority_statement_digest")}} {
		if digest(check.body) != check.claimed {
			return "STATEMENT_DIGEST_MISMATCH"
		}
	}
	proposalDigest := text(evidence, "producer_statement_digest")
	if text(policy, "proposal_digest") != proposalDigest || text(authority, "proposal_digest") != proposalDigest {
		return "PROPOSAL_DIGEST_MISMATCH"
	}
	if text(policy, "decision") != "allow" {
		return "SUBJECT_MISMATCH"
	}
	signatures := child(certificate, "signatures")
	checks := []struct {
		signature     cj1.Object
		bodyKey, role string
		scope         []string
		domain        string
		body          []byte
		invalid       string
	}{
		{child(signatures, "producer"), text(producer, "producer_key_id"), "producer", []string{text(producer, "agent_id"), text(producer, "actor_authority"), text(authority, "authority_root")}, proposalDomain, producerBytes, "INVALID_PRODUCER_SIGNATURE"},
		{child(signatures, "policy_authority"), text(policy, "policy_key_id"), "policy", []string{text(policy, "policy_id"), text(policy, "policy_version"), text(policy, "policy_epoch")}, policyDomain, policyBytes, "INVALID_POLICY_SIGNATURE"},
		{child(signatures, "authority_registry"), text(authority, "authority_key_id"), "registry", []string{text(authority, "authority_root"), text(authority, "authority_epoch")}, authorityDomain, authorityBytes, "INVALID_AUTHORITY_SIGNATURE"},
	}
	for _, check := range checks {
		if code := verifySignature(check.signature, check.bodyKey, trust, check.role, check.scope, check.domain, check.body, check.invalid); code != "" {
			return code
		}
	}
	return ""
}

func verifySignature(signature cj1.Object, bodyKey string, trust *Trust, role string, scope []string, domain string, body []byte, invalid string) string {
	if text(signature, "algorithm") != "Ed25519" {
		return "UNSUPPORTED_SIGNATURE_ALGORITHM"
	}
	if text(signature, "key_id") != bodyKey {
		return "KEY_ID_MISMATCH"
	}
	publicKey, code := trust.Resolve(role, scope, bodyKey)
	if code != "" {
		return code
	}
	signatureBytes, valid := decodeB64u(text(signature, "signature_b64u"), ed25519.SignatureSize)
	if !valid {
		return invalid
	}
	preimage := append(append([]byte(domain), 0), body...)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), preimage, signatureBytes) {
		return invalid
	}
	return ""
}

func verifyBindings(certificate cj1.Object) string {
	subject, context, decision, bindings := child(certificate, "subject"), child(certificate, "context"), child(certificate, "decision"), child(certificate, "bindings")
	evidence := child(certificate, "evidence")
	producer, policy, authority := child(evidence, "producer_statement"), child(evidence, "policy_statement"), child(evidence, "authority_statement")
	if text(producer, "workflow_id") != text(subject, "workflow_id") {
		return "CROSS_WORKFLOW_REPLAY"
	}
	if text(producer, "node_id") != text(subject, "node_id") {
		return "CROSS_NODE_REPLAY"
	}
	if text(producer, "attempt_id") != text(subject, "attempt_id") {
		return "ATTEMPT_MISMATCH"
	}
	if text(producer, "agent_id") != text(subject, "agent_id") {
		return "SUBJECT_MISMATCH"
	}
	if text(producer, "actor_authority") != text(subject, "actor_authority") {
		return "ACTOR_AUTHORITY_MISMATCH"
	}
	if text(producer, "input_digest") != text(subject, "input_digest") {
		return "INPUT_DIGEST_MISMATCH"
	}
	if text(producer, "output_digest") != text(subject, "output_digest") {
		return "OUTPUT_DIGEST_MISMATCH"
	}
	if text(authority, "agent_id") != text(subject, "agent_id") {
		return "SUBJECT_MISMATCH"
	}
	if text(authority, "producer_key_id") != text(producer, "producer_key_id") {
		return "KEY_ID_MISMATCH"
	}
	if text(authority, "actor_authority") != text(subject, "actor_authority") {
		return "ACTOR_AUTHORITY_MISMATCH"
	}
	for _, statement := range []cj1.Object{policy, authority} {
		if text(statement, "workflow_id") != text(subject, "workflow_id") {
			return "CROSS_WORKFLOW_REPLAY"
		}
		if text(statement, "node_id") != text(subject, "node_id") {
			return "CROSS_NODE_REPLAY"
		}
		if text(statement, "attempt_id") != text(subject, "attempt_id") {
			return "ATTEMPT_MISMATCH"
		}
	}
	if text(context, "policy_id") != text(policy, "policy_id") || text(context, "policy_version") != text(policy, "policy_version") || text(context, "policy_epoch") != text(policy, "policy_epoch") {
		return "STALE_POLICY_EPOCH"
	}
	if text(context, "authority_root") != text(authority, "authority_root") || text(context, "authority_epoch") != text(authority, "authority_epoch") {
		return "STALE_AUTHORITY_EPOCH"
	}
	if text(context, "workflow_epoch") != text(authority, "workflow_epoch") {
		return "STALE_WORKFLOW_EPOCH"
	}
	if text(context, "agent_revocation_generation") != text(authority, "agent_revocation_generation") {
		return "ACTOR_REVOKED"
	}
	if text(context, "workflow_revocation_generation") != text(authority, "workflow_revocation_generation") {
		return "WORKFLOW_REVOKED"
	}
	if text(decision, "commit_id") != text(producer, "commit_id") || text(decision, "nonce") != text(producer, "nonce") {
		return "SUBJECT_MISMATCH"
	}
	expected, _ := decimal(text(bindings, "expected_node_version"))
	committed, _ := decimal(text(bindings, "committed_node_version"))
	if text(bindings, "expected_node_version") != text(producer, "expected_node_version") || committed != expected+1 {
		return "NODE_VERSION_CONFLICT"
	}
	if text(bindings, "predecessor_root") != text(producer, "predecessor_root") {
		return "PREDECESSOR_ROOT_MISMATCH"
	}
	predecessors, _ := array(bindings["predecessors"])
	predecessorBytes := canonical(predecessors)
	if digest(predecessorBytes) != text(bindings, "predecessor_root") {
		return "PREDECESSOR_ROOT_MISMATCH"
	}
	for _, item := range predecessors {
		predecessor, _ := object(item)
		if text(predecessor, "workflow_id") != text(subject, "workflow_id") {
			return "CROSS_WORKFLOW_PREDECESSOR"
		}
	}
	committedAt, _ := decimal(text(decision, "committed_at_ms"))
	for _, statement := range []cj1.Object{producer, policy, authority} {
		issued, _ := decimal(text(statement, "issued_at_ms"))
		expires, _ := decimal(text(statement, "expires_at_ms"))
		if issued >= expires || committedAt < issued {
			return "ATTESTATION_NOT_YET_VALID"
		}
		if committedAt > expires {
			return "ATTESTATION_EXPIRED"
		}
	}
	return ""
}

type CurrentInputs struct {
	AuthorityStatus         []byte
	RequestNonce            string
	NowMS                   string
	HighestTrustLogSequence string
	HighestTrustLogHead     string
	MaximumStalenessMS      string
}

func VerifyCurrent(envelope []byte, trust *Trust, input CurrentInputs) Result {
	if trust == nil {
		return failure("UNKNOWN_KEY")
	}
	if _, valid := decodeB64u(input.RequestNonce, 16); !valid {
		return failure("INVALID_BASE64URL")
	}
	if _, valid := decodeB64u(input.HighestTrustLogHead, 32); !valid {
		return failure("INVALID_BASE64URL")
	}
	now, validNow := decimal(input.NowMS)
	highest, validHighest := decimal(input.HighestTrustLogSequence)
	maximum, validMaximum := decimal(input.MaximumStalenessMS)
	if !validNow || !validHighest || !validMaximum {
		return failure("INVALID_DECIMAL_STRING")
	}
	historical := VerifyHistorical(envelope, trust)
	if !historical.OK {
		return historical
	}
	if input.AuthorityStatus == nil {
		return failure("AUTHORITY_STATUS_REQUIRED")
	}
	statusValue, parseErr := cj1.Parse(input.AuthorityStatus, cj1.MaxPayloadBytes)
	if parseErr != nil {
		return failure(parseErr.Code)
	}
	if code := validateSchema(statusValue, statusSchema); code != "" {
		return failure(code)
	}
	if code := validateScalars(statusValue, ""); code != "" {
		return failure(code)
	}
	status, _ := object(statusValue)
	body, signature := child(status, "body"), child(status, "signature")
	if text(body, "protocol_version") != "APCC-1.0-draft" {
		return failure("UNKNOWN_PROTOCOL_VERSION")
	}
	if text(body, "statement_type") != "apcc.authority-status" {
		return failure("UNSUPPORTED_STATEMENT_TYPE")
	}
	if text(body, "status") != "current" && text(body, "status") != "revoked" {
		return failure("AUTHORITY_STATUS_REVOKED")
	}
	if text(body, "superseded") != "yes" && text(body, "superseded") != "no" {
		return failure("AUTHORITY_STATUS_SUPERSEDED")
	}
	header, context := child(historical.Certificate, "header"), child(historical.Certificate, "context")
	if text(body, "authority_store_id") != text(header, "authority_store_id") {
		return failure("AUTHORITY_STATUS_CERTIFICATE_MISMATCH")
	}
	if text(signature, "algorithm") != "Ed25519" {
		return failure("UNSUPPORTED_SIGNATURE_ALGORITHM")
	}
	if text(signature, "key_id") != text(body, "status_key_id") {
		return failure("KEY_ID_MISMATCH")
	}
	if code := verifySignature(signature, text(body, "status_key_id"), trust, "status", []string{text(body, "authority_store_id")}, statusDomain, canonical(body), "AUTHORITY_STATUS_INVALID_SIGNATURE"); code != "" {
		return failure(code)
	}
	if text(body, "request_nonce") != input.RequestNonce {
		return failure("AUTHORITY_STATUS_NONCE_MISMATCH")
	}
	if text(body, "certificate_digest") != historical.CertificateDigest || text(body, "certificate_sequence") != text(header, "certificate_sequence") {
		return failure("AUTHORITY_STATUS_CERTIFICATE_MISMATCH")
	}
	if text(body, "actor_revocation_generation") != text(context, "agent_revocation_generation") {
		return failure("ACTOR_REVOKED")
	}
	if text(body, "workflow_revocation_generation") != text(context, "workflow_revocation_generation") {
		return failure("WORKFLOW_REVOKED")
	}
	thisUpdate, _ := decimal(text(body, "this_update_ms"))
	nextUpdate, _ := decimal(text(body, "next_update_ms"))
	if thisUpdate > now {
		return failure("ATTESTATION_NOT_YET_VALID")
	}
	if nextUpdate < now || thisUpdate >= nextUpdate || now-thisUpdate > maximum {
		return failure("AUTHORITY_STATUS_EXPIRED")
	}
	sequence, _ := decimal(text(body, "trust_log_sequence"))
	if sequence < highest || (sequence == highest && text(body, "trust_log_head") != input.HighestTrustLogHead) {
		return failure("AUTHORITY_STATUS_ROLLBACK")
	}
	if text(body, "status") != "current" {
		return failure("AUTHORITY_STATUS_REVOKED")
	}
	if text(body, "superseded") != "no" {
		return failure("AUTHORITY_STATUS_SUPERSEDED")
	}
	return historical
}

func FingerprintPublicKey(publicKey []byte) string {
	value := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func SortedTrustIdentities(trust *Trust) []string {
	items := make([]string, 0, len(trust.bindings))
	for identity := range trust.bindings {
		items = append(items, identity)
	}
	sort.Strings(items)
	return items
}
