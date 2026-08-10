package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
)

const (
	errCredentialFormat       envelopeError = "credential_format"
	errCredentialValidity     envelopeError = "credential_validity"
	errIssuerSignatureSuite   envelopeError = "issuer_signature_suite"
	errCredentialSignatureLen envelopeError = "signature_length"
	errRegistryMalformed      envelopeError = "registry_malformed"
	errPolicyCount            envelopeError = "policy_count"
	errPolicyOrder            envelopeError = "policy_order"
	errCredentialBoolean      envelopeError = "invalid_boolean"
	errNotYetIssued           envelopeError = "not_yet_issued"
	errNotYetValid            envelopeError = "not_yet_valid"
	errExpired                envelopeError = "expired"
	errSubjectBinding         envelopeError = "subject_binding_mismatch"
	errIssuerNotAccepted      envelopeError = "issuer_not_accepted"
	errSchemaNotAccepted      envelopeError = "schema_not_accepted"
	errIssuerEvidenceIssuer   envelopeError = "issuer_evidence_issuer_mismatch"
	errIssuerEvidenceBinding  envelopeError = "issuer_evidence_commitment_mismatch"
	errIssuerEvidenceSuite    envelopeError = "issuer_evidence_suite_mismatch"
	errIssuanceLogRequired    envelopeError = "issuance_log_required"
	errIssuanceLogEvidence    envelopeError = "issuance_log_evidence_mismatch"
	errMissingRegistry        envelopeError = "missing_status_registry"
	errMissingStatusEvidence  envelopeError = "missing_status_evidence"
	errRegistryID             envelopeError = "registry_id_mismatch"
	errRegistryIssuer         envelopeError = "registry_issuer_mismatch"
	errRegistrySchema         envelopeError = "registry_schema_mismatch"
	errRegistryFuture         envelopeError = "registry_from_future"
	errRegistryStale          envelopeError = "registry_stale"
	errStatusEvidenceRegistry envelopeError = "status_evidence_registry_mismatch"
	errStatusEvidenceCred     envelopeError = "status_evidence_credential_mismatch"
	errStatusEvidenceRoot     envelopeError = "status_evidence_root_mismatch"
	errStatusEvidenceSequence envelopeError = "status_evidence_sequence_mismatch"
	errCredentialRevoked      envelopeError = "credential_revoked"
	errCredentialSuspended    envelopeError = "credential_suspended"
)

type credentialReader struct {
	body   []byte
	offset int
	err    envelopeError
}

func (r *credentialReader) take(length int) []byte {
	if r.err != "" {
		return nil
	}
	if length < 0 || r.offset+length > len(r.body) {
		r.err = errUnexpectedEnd
		return nil
	}
	value := r.body[r.offset : r.offset+length]
	r.offset += length
	return value
}

func (r *credentialReader) u8() byte {
	value := r.take(1)
	if value == nil {
		return 0
	}
	return value[0]
}

func (r *credentialReader) u16() uint16 {
	value := r.take(2)
	if value == nil {
		return 0
	}
	return binary.BigEndian.Uint16(value)
}

func (r *credentialReader) u64() uint64 {
	value := r.take(8)
	if value == nil {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}

func (r *credentialReader) digest() [48]byte {
	var value [48]byte
	copy(value[:], r.take(len(value)))
	return value
}

func (r *credentialReader) optionalU64() *uint64 {
	tag := r.u8()
	if r.err != "" {
		return nil
	}
	switch tag {
	case 0:
		return nil
	case 1:
		value := r.u64()
		return &value
	default:
		r.err = errInvalidOption
		return nil
	}
}

func (r *credentialReader) optionalDigest() *[48]byte {
	tag := r.u8()
	if r.err != "" {
		return nil
	}
	switch tag {
	case 0:
		return nil
	case 1:
		value := r.digest()
		return &value
	default:
		r.err = errInvalidOption
		return nil
	}
}

func (r *credentialReader) length(maximum uint32) uint32 {
	if r.err != "" {
		return 0
	}
	value, width, decodeErr := decodeLength(r.body[r.offset:])
	if decodeErr != "" {
		r.err = decodeErr
		return 0
	}
	if value > maximum {
		r.err = errPolicyCount
		return 0
	}
	r.offset += width
	return value
}

func (r *credentialReader) finish() envelopeError {
	if r.err != "" {
		return r.err
	}
	if r.offset != len(r.body) {
		return errTrailingData
	}
	return ""
}

type credentialStatement struct {
	issuer          [48]byte
	subjectBinding  [48]byte
	schemaID        [48]byte
	issuanceHeight  uint64
	validFrom       uint64
	validUntil      *uint64
	statusRegistry  *[48]byte
	issuanceLogRoot *[48]byte
}

func decodeCredentialStatement(r *credentialReader) (credentialStatement, envelopeError) {
	format := r.u16()
	statement := credentialStatement{issuer: r.digest(), subjectBinding: r.digest(), schemaID: r.digest()}
	_ = r.digest() // Claims remain committed and private to this semantic verifier.
	statement.issuanceHeight = r.u64()
	statement.validFrom = r.u64()
	statement.validUntil = r.optionalU64()
	statement.statusRegistry = r.optionalDigest()
	statement.issuanceLogRoot = r.optionalDigest()
	_ = r.optionalDigest() // Terms commitment is structurally decoded but not disclosed.
	if r.err != "" {
		return credentialStatement{}, r.err
	}
	if format != 1 {
		return credentialStatement{}, errCredentialFormat
	}
	if statement.validUntil != nil && *statement.validUntil < statement.validFrom {
		return credentialStatement{}, errCredentialValidity
	}
	return statement, ""
}

func envelopeBody(input []byte, typeTag uint16, maximum uint32) ([]byte, envelopeError) {
	if _, framingErr := inspectEnvelope(input, typeTag, 1, maximum); framingErr != "" {
		return nil, framingErr
	}
	_, width, _ := decodeLength(input[4:])
	return input[4+width:], ""
}

type decodedCredential struct {
	statement credentialStatement
	suite     cryptoSuite
}

func decodeCredentialEnvelope(input []byte) (decodedCredential, envelopeError) {
	body, framingErr := envelopeBody(input, 0x0024, 5001)
	if framingErr != "" {
		return decodedCredential{}, framingErr
	}
	r := credentialReader{body: body}
	statement, statementErr := decodeCredentialStatement(&r)
	if statementErr != "" {
		return decodedCredential{}, statementErr
	}
	suiteBody := r.take(6)
	if r.err != "" {
		return decodedCredential{}, r.err
	}
	suite, suiteErr := registeredSuite(suiteBody)
	if suiteErr != "" {
		return decodedCredential{}, suiteErr
	}
	if suite.family != 1 || (suite.parameter != 65 && suite.parameter != 87) {
		return decodedCredential{}, errIssuerSignatureSuite
	}
	signatureLength := r.length(uint32(suite.signatureLength))
	if r.err != "" {
		return decodedCredential{}, r.err
	}
	if int(signatureLength) != suite.signatureLength {
		return decodedCredential{}, errCredentialSignatureLen
	}
	_ = r.take(int(signatureLength))
	if finishErr := r.finish(); finishErr != "" {
		return decodedCredential{}, finishErr
	}
	return decodedCredential{statement: statement, suite: suite}, ""
}

type decodedStatusRegistry struct {
	registryID      [48]byte
	issuer          [48]byte
	schemaID        [48]byte
	statusRoot      [48]byte
	sequence        uint64
	effectiveHeight uint64
}

func decodeStatusRegistryEnvelope(input []byte) (decodedStatusRegistry, envelopeError) {
	body, framingErr := envelopeBody(input, 0x0025, 208)
	if framingErr != "" {
		return decodedStatusRegistry{}, framingErr
	}
	if len(body) != 208 {
		return decodedStatusRegistry{}, errBodyLengthMismatch
	}
	r := credentialReader{body: body}
	registry := decodedStatusRegistry{
		registryID: r.digest(), issuer: r.digest(), schemaID: r.digest(), statusRoot: r.digest(),
		sequence: r.u64(), effectiveHeight: r.u64(),
	}
	if finishErr := r.finish(); finishErr != "" {
		return decodedStatusRegistry{}, finishErr
	}
	zero := [48]byte{}
	if registry.registryID == zero || registry.issuer == zero || registry.schemaID == zero ||
		registry.statusRoot == zero || registry.sequence == 0 {
		return decodedStatusRegistry{}, errRegistryMalformed
	}
	return registry, ""
}

type decodedAcceptancePolicy struct {
	issuers            [][48]byte
	schemas            [][48]byte
	maximumStatusAge   uint64
	requireStatus      bool
	requireIssuanceLog bool
}

func readBoolean(r *credentialReader) bool {
	value := r.u8()
	if r.err == "" && value > 1 {
		r.err = errCredentialBoolean
	}
	return value == 1
}

func strictlyIncreasingDigests(values [][48]byte) bool {
	for index := 1; index < len(values); index++ {
		if bytes.Compare(values[index-1][:], values[index][:]) >= 0 {
			return false
		}
	}
	return true
}

func decodeAcceptancePolicyEnvelope(input []byte) (decodedAcceptancePolicy, envelopeError) {
	body, framingErr := envelopeBody(input, 0x0026, 3084)
	if framingErr != "" {
		return decodedAcceptancePolicy{}, framingErr
	}
	r := credentialReader{body: body}
	policy := decodedAcceptancePolicy{}
	issuerCount := r.length(32)
	for index := uint32(0); index < issuerCount && r.err == ""; index++ {
		policy.issuers = append(policy.issuers, r.digest())
	}
	schemaCount := r.length(32)
	for index := uint32(0); index < schemaCount && r.err == ""; index++ {
		policy.schemas = append(policy.schemas, r.digest())
	}
	policy.maximumStatusAge = r.u64()
	policy.requireStatus = readBoolean(&r)
	policy.requireIssuanceLog = readBoolean(&r)
	if finishErr := r.finish(); finishErr != "" {
		return decodedAcceptancePolicy{}, finishErr
	}
	if !strictlyIncreasingDigests(policy.issuers) || !strictlyIncreasingDigests(policy.schemas) {
		return decodedAcceptancePolicy{}, errPolicyOrder
	}
	return policy, ""
}

func containsDigest(values [][48]byte, expected [48]byte) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type credentialVerificationInput struct {
	presentationHeight uint64
	presentationTime   uint64
	subjectMode        string
	status             string
	issuerEvidence     string
	statusEvidence     string
}

func verifyCredentialPresentation(
	credential decodedCredential,
	registry decodedStatusRegistry,
	policy decodedAcceptancePolicy,
	input credentialVerificationInput,
) envelopeError {
	statement := credential.statement
	if statement.issuanceHeight > input.presentationHeight {
		return errNotYetIssued
	}
	if input.presentationTime < statement.validFrom {
		return errNotYetValid
	}
	if statement.validUntil != nil && input.presentationTime > *statement.validUntil {
		return errExpired
	}
	if input.subjectMode != "match" {
		return errSubjectBinding
	}
	if !containsDigest(policy.issuers, statement.issuer) {
		return errIssuerNotAccepted
	}
	if !containsDigest(policy.schemas, statement.schemaID) {
		return errSchemaNotAccepted
	}
	switch input.issuerEvidence {
	case "match":
	case "wrong_issuer":
		return errIssuerEvidenceIssuer
	case "wrong_commitment":
		return errIssuerEvidenceBinding
	case "wrong_suite":
		return errIssuerEvidenceSuite
	case "missing_log":
		if policy.requireIssuanceLog {
			return errIssuanceLogEvidence
		}
	default:
		return errIssuerEvidenceBinding
	}
	if policy.requireIssuanceLog && statement.issuanceLogRoot == nil {
		return errIssuanceLogRequired
	}
	if statement.statusRegistry == nil {
		if policy.requireStatus {
			return errMissingRegistry
		}
		return ""
	}
	switch input.statusEvidence {
	case "missing_registry":
		return errMissingRegistry
	case "missing_evidence":
		return errMissingStatusEvidence
	}
	if registry.registryID != *statement.statusRegistry {
		return errRegistryID
	}
	if registry.issuer != statement.issuer {
		return errRegistryIssuer
	}
	if registry.schemaID != statement.schemaID {
		return errRegistrySchema
	}
	if registry.effectiveHeight > input.presentationHeight {
		return errRegistryFuture
	}
	if input.presentationHeight-registry.effectiveHeight > policy.maximumStatusAge {
		return errRegistryStale
	}
	switch input.statusEvidence {
	case "match":
	case "wrong_registry":
		return errStatusEvidenceRegistry
	case "wrong_credential":
		return errStatusEvidenceCred
	case "wrong_root":
		return errStatusEvidenceRoot
	case "wrong_sequence":
		return errStatusEvidenceSequence
	default:
		return errMissingStatusEvidence
	}
	switch input.status {
	case "active":
		return ""
	case "revoked":
		return errCredentialRevoked
	case "suspended":
		return errCredentialSuspended
	default:
		return errMissingStatusEvidence
	}
}

func encodeCanonicalLength(value uint32) []byte {
	output := make([]byte, 0, 5)
	for {
		current := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			current |= 0x80
		}
		output = append(output, current)
		if value == 0 {
			return output
		}
	}
}

func rebuildEnvelope(input, body []byte) []byte {
	output := append([]byte(nil), input[:4]...)
	output = append(output, encodeCanonicalLength(uint32(len(body)))...)
	return append(output, body...)
}

func mutateCredentialFamilyEnvelope(input []byte, mutation string) ([]byte, error) {
	switch mutation {
	case "wrong_type":
		output := append([]byte(nil), input...)
		copy(output[:2], []byte{0xff, 0xff})
		return output, nil
	case "wrong_schema":
		output := append([]byte(nil), input...)
		copy(output[2:4], []byte{0, 2})
		return output, nil
	}
	if mutation != "duplicate_issuer" && mutation != "duplicate_schema" && mutation != "nonminimal_count" {
		return mutateEnvelopeBody(input, mutation)
	}
	_, width, decodeErr := decodeLength(input[4:])
	if decodeErr != "" {
		return nil, fmt.Errorf("invalid base envelope: %s", decodeErr)
	}
	body := append([]byte(nil), input[4+width:]...)
	original := body
	switch mutation {
	case "duplicate_issuer":
		if len(body) < 49 || body[0] != 1 {
			return nil, fmt.Errorf("unexpected policy issuer shape")
		}
		body = append([]byte{2}, append(append([]byte(nil), body[1:49]...), body[1:]...)...)
	case "duplicate_schema":
		if len(body) < 98 || body[0] != 1 || body[49] != 1 {
			return nil, fmt.Errorf("unexpected policy schema shape")
		}
		body = append(append([]byte(nil), original[:49]...), 2)
		body = append(body, original[50:98]...)
		body = append(body, original[50:]...)
	case "nonminimal_count":
		body = append([]byte{0x81, 0x00}, body[1:]...)
	}
	return rebuildEnvelope(input, body), nil
}

func verifyCredentialVector(path string, v vector) error {
	if len(v.fields) != 12 {
		return fmt.Errorf("case %q: expected 12 fields", v.name)
	}
	source := filepath.Join(filepath.Dir(path), filepath.FromSlash(v.fields[1]))
	credentialEnvelope, err := readNamedHex(source, "credential_envelope_hex")
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	registryEnvelope, err := readNamedHex(source, "status_registry_envelope_hex")
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	policyEnvelope, err := readNamedHex(source, "acceptance_policy_envelope_hex")
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	credentialEnvelope, err = mutateCredentialFamilyEnvelope(credentialEnvelope, v.fields[2])
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	registryEnvelope, err = mutateCredentialFamilyEnvelope(registryEnvelope, v.fields[3])
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	policyEnvelope, err = mutateCredentialFamilyEnvelope(policyEnvelope, v.fields[4])
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	height, err := parseUintField(v.fields[6], 64)
	if err != nil {
		return err
	}
	timestamp, err := parseUintField(v.fields[7], 64)
	if err != nil {
		return err
	}
	credential, actual := decodeCredentialEnvelope(credentialEnvelope)
	if actual == "" {
		var registry decodedStatusRegistry
		registry, actual = decodeStatusRegistryEnvelope(registryEnvelope)
		if actual == "" {
			var policy decodedAcceptancePolicy
			policy, actual = decodeAcceptancePolicyEnvelope(policyEnvelope)
			if actual == "" {
				actual = verifyCredentialPresentation(credential, registry, policy, credentialVerificationInput{
					presentationHeight: height, presentationTime: timestamp, subjectMode: v.fields[5],
					status: v.fields[8], issuerEvidence: v.fields[9], statusEvidence: v.fields[10],
				})
			}
		}
	}
	expected := envelopeError(v.fields[11])
	if expected == "ok" {
		expected = ""
	}
	if actual != expected {
		return fmt.Errorf("case %q: expected %q, got %q", v.name, expected, actual)
	}
	return nil
}
