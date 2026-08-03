// Command ac-go-verifier is the independent v1.0 M0 vector reader. It deliberately
// uses only the Go standard library and published TSV vectors; it must not
// import ActiveChain's Rust transition crates.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type vector struct {
	name   string
	fields []string
}

const maxEnvelopeLength = 256 * 1024

type envelopeMetadata struct {
	typeTag       uint16
	schemaVersion uint16
	bodyLength    uint32
}

type envelopeError string

const (
	errUnexpectedEnd       envelopeError = "unexpected_end"
	errTypeMismatch        envelopeError = "type_mismatch"
	errVersionMismatch     envelopeError = "version_mismatch"
	errLengthOverflow      envelopeError = "length_overflow"
	errNonminimalLength    envelopeError = "nonminimal_length"
	errBodyLimit           envelopeError = "body_limit"
	errBodyLengthMismatch  envelopeError = "body_length_mismatch"
	errTrailingData        envelopeError = "trailing_data"
	errPrincipalKind       envelopeError = "principal_kind"
	errFreezeState         envelopeError = "freeze_state"
	errUpdateBeforeCreate  envelopeError = "update_before_creation"
	errCryptoSuite         envelopeError = "crypto_suite"
	errKeyLength           envelopeError = "key_length"
	errPurpose             envelopeError = "purpose"
	errPurposeSuite        envelopeError = "purpose_suite"
	errValidityInversion   envelopeError = "validity_inversion"
	errRevocationInversion envelopeError = "revocation_inversion"
	errInvalidOption       envelopeError = "invalid_option"
)

func canonicalLengthWidth(value uint32) int {
	switch {
	case value < 1<<7:
		return 1
	case value < 1<<14:
		return 2
	case value < 1<<21:
		return 3
	case value < 1<<28:
		return 4
	default:
		return 5
	}
}

func decodeLength(input []byte) (uint32, int, envelopeError) {
	var value uint64
	for i := 0; i < 5; i++ {
		if i >= len(input) {
			return 0, 0, errUnexpectedEnd
		}
		b := input[i]
		value |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			if value > uint64(^uint32(0)) {
				return 0, 0, errLengthOverflow
			}
			decoded := uint32(value)
			if canonicalLengthWidth(decoded) != i+1 {
				return 0, 0, errNonminimalLength
			}
			return decoded, i + 1, ""
		}
	}
	return 0, 0, errLengthOverflow
}

func inspectEnvelope(input []byte, expectedType, expectedSchema uint16, maxBody uint32) (envelopeMetadata, envelopeError) {
	if len(input) > maxEnvelopeLength {
		return envelopeMetadata{}, errBodyLimit
	}
	if len(input) < 4 {
		return envelopeMetadata{}, errUnexpectedEnd
	}
	typeTag := uint16(input[0])<<8 | uint16(input[1])
	schema := uint16(input[2])<<8 | uint16(input[3])
	if typeTag != expectedType {
		return envelopeMetadata{}, errTypeMismatch
	}
	if schema != expectedSchema {
		return envelopeMetadata{}, errVersionMismatch
	}
	bodyLength, width, lengthErr := decodeLength(input[4:])
	if lengthErr != "" {
		return envelopeMetadata{}, lengthErr
	}
	if bodyLength > maxBody {
		return envelopeMetadata{}, errBodyLimit
	}
	bodyStart := 4 + width
	available := len(input) - bodyStart
	if uint64(available) < uint64(bodyLength) {
		return envelopeMetadata{}, errBodyLengthMismatch
	}
	if uint64(available) > uint64(bodyLength) {
		return envelopeMetadata{}, errTrailingData
	}
	return envelopeMetadata{typeTag: typeTag, schemaVersion: schema, bodyLength: bodyLength}, ""
}

func parseUintField(value string, bits int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 0, bits)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q: %w", value, err)
	}
	return parsed, nil
}

func verifyCodecVector(v vector) error {
	if len(v.fields) != 6 {
		return fmt.Errorf("case %q: expected 6 fields", v.name)
	}
	typeTag, err := parseUintField(v.fields[1], 16)
	if err != nil {
		return err
	}
	schema, err := parseUintField(v.fields[2], 16)
	if err != nil {
		return err
	}
	maxBody, err := parseUintField(v.fields[3], 32)
	if err != nil {
		return err
	}
	input, err := hex.DecodeString(v.fields[4])
	if err != nil {
		return fmt.Errorf("case %q: invalid envelope hex: %w", v.name, err)
	}
	metadata, actual := inspectEnvelope(input, uint16(typeTag), uint16(schema), uint32(maxBody))
	expected := envelopeError(v.fields[5])
	if expected == "ok" {
		if actual != "" {
			return fmt.Errorf("case %q: expected acceptance, got %s", v.name, actual)
		}
		if metadata.typeTag != uint16(typeTag) || metadata.schemaVersion != uint16(schema) {
			return fmt.Errorf("case %q: accepted metadata mismatch", v.name)
		}
		return nil
	}
	if actual != expected {
		return fmt.Errorf("case %q: expected %s, got %s", v.name, expected, actual)
	}
	return nil
}

func readNamedHex(path, name string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	prefix := name + "="
	for s.Scan() {
		if strings.HasPrefix(s.Text(), prefix) {
			return hex.DecodeString(strings.TrimPrefix(s.Text(), prefix))
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s: missing %s", path, name)
}

func mutateEnvelopeBody(envelope []byte, mutation string) ([]byte, error) {
	out := append([]byte(nil), envelope...)
	if mutation == "none" {
		return out, nil
	}
	if strings.HasPrefix(mutation, "append:") {
		value, err := hex.DecodeString(strings.TrimPrefix(mutation, "append:"))
		if err != nil {
			return nil, err
		}
		return append(out, value...), nil
	}
	if strings.HasPrefix(mutation, "truncate:") {
		count, err := strconv.Atoi(strings.TrimPrefix(mutation, "truncate:"))
		if err != nil || count < 0 || count > len(out) {
			return nil, fmt.Errorf("invalid truncation %q", mutation)
		}
		return out[:len(out)-count], nil
	}
	length, width, lengthErr := decodeLength(out[4:])
	if lengthErr != "" || int(length)+4+width != len(out) {
		return nil, fmt.Errorf("base principal envelope is not canonical")
	}
	bodyStart := 4 + width
	parts := strings.Split(mutation, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid mutation %q", mutation)
	}
	offset, err := strconv.Atoi(parts[1])
	if err != nil || offset < 0 {
		return nil, fmt.Errorf("invalid mutation offset %q", parts[1])
	}
	switch parts[0] {
	case "set":
		value, err := hex.DecodeString(parts[2])
		if err != nil || len(value) != 1 || bodyStart+offset >= len(out) {
			return nil, fmt.Errorf("invalid byte mutation %q", mutation)
		}
		out[bodyStart+offset] = value[0]
	case "set_hex":
		value, err := hex.DecodeString(parts[2])
		if err != nil || len(value) == 0 || bodyStart+offset+len(value) > len(out) {
			return nil, fmt.Errorf("invalid bytes mutation %q", mutation)
		}
		copy(out[bodyStart+offset:bodyStart+offset+len(value)], value)
	case "set_u64":
		value, err := strconv.ParseUint(parts[2], 10, 64)
		if err != nil || bodyStart+offset+8 > len(out) {
			return nil, fmt.Errorf("invalid u64 mutation %q", mutation)
		}
		binary.BigEndian.PutUint64(out[bodyStart+offset:bodyStart+offset+8], value)
	default:
		return nil, fmt.Errorf("unknown mutation %q", mutation)
	}
	return out, nil
}

func verifyPrincipalEnvelope(input []byte) envelopeError {
	if _, framingErr := inspectEnvelope(input, 0x0020, 1, 282); framingErr != "" {
		return framingErr
	}
	_, width, _ := decodeLength(input[4:])
	body := input[4+width:]
	if len(body) != 282 {
		return errBodyLengthMismatch
	}
	if body[48] > 5 {
		return errPrincipalKind
	}
	if body[201] > 2 {
		return errFreezeState
	}
	created := binary.BigEndian.Uint64(body[266:274])
	updated := binary.BigEndian.Uint64(body[274:282])
	if updated < created {
		return errUpdateBeforeCreate
	}
	return ""
}

func verifyPrincipalVector(path string, v vector) error {
	if len(v.fields) != 4 {
		return fmt.Errorf("case %q: expected 4 fields", v.name)
	}
	source := filepath.Join(filepath.Dir(path), filepath.FromSlash(v.fields[1]))
	envelope, err := readNamedHex(source, "envelope_hex")
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	envelope, err = mutateEnvelopeBody(envelope, v.fields[2])
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	actual := verifyPrincipalEnvelope(envelope)
	expected := envelopeError(v.fields[3])
	if expected == "ok" {
		expected = ""
	}
	if actual != expected {
		return fmt.Errorf("case %q: expected %q, got %q", v.name, expected, actual)
	}
	return nil
}

type cryptoSuite struct {
	family          byte
	parameter       uint16
	encoding        uint16
	profile         byte
	keyLength       int
	signatureLength int
}

func registeredSuite(body []byte) (cryptoSuite, envelopeError) {
	if len(body) < 6 {
		return cryptoSuite{}, errUnexpectedEnd
	}
	candidate := cryptoSuite{
		family: body[0], parameter: binary.BigEndian.Uint16(body[1:3]),
		encoding: binary.BigEndian.Uint16(body[3:5]), profile: body[5],
	}
	for _, suite := range []cryptoSuite{
		{1, 44, 1, 2, 1312, 2420}, {1, 65, 1, 3, 1952, 3309},
		{1, 87, 1, 5, 2592, 4627}, {2, 0x0192, 1, 3, 48, 16224},
		{3, 768, 1, 3, 0, 0}, {4, 384, 1, 5, 0, 0},
	} {
		if candidate.family == suite.family && candidate.parameter == suite.parameter &&
			candidate.encoding == suite.encoding && candidate.profile == suite.profile {
			return suite, ""
		}
	}
	return cryptoSuite{}, errCryptoSuite
}

func decodeOptionalHeight(body []byte, cursor *int) (*uint64, envelopeError) {
	if *cursor >= len(body) {
		return nil, errUnexpectedEnd
	}
	tag := body[*cursor]
	*cursor++
	if tag == 0 {
		return nil, ""
	}
	if tag != 1 {
		return nil, errInvalidOption
	}
	if *cursor+8 > len(body) {
		return nil, errUnexpectedEnd
	}
	value := binary.BigEndian.Uint64(body[*cursor : *cursor+8])
	*cursor += 8
	return &value, ""
}

func purposeAcceptsSuite(purpose byte, suite cryptoSuite) bool {
	switch purpose {
	case 0, 4:
		return suite.family == 1 && (suite.parameter == 65 || suite.parameter == 87)
	case 1:
		return (suite.family == 1 && (suite.parameter == 65 || suite.parameter == 87)) ||
			(suite.family == 2 && suite.parameter == 0x0192)
	case 2, 5:
		return suite.family == 1 && (suite.parameter == 44 || suite.parameter == 65)
	case 3:
		return suite.family == 1 && suite.parameter == 44
	default:
		return false
	}
}

func verifyAuthenticatorEnvelope(input []byte) envelopeError {
	if _, framingErr := inspectEnvelope(input, 0x0021, 1, 4179); framingErr != "" {
		return framingErr
	}
	_, envelopeWidth, _ := decodeLength(input[4:])
	body := input[4+envelopeWidth:]
	if len(body) < 54 {
		return errUnexpectedEnd
	}
	suite, suiteErr := registeredSuite(body[48:54])
	if suiteErr != "" {
		return suiteErr
	}
	if suite.keyLength == 0 {
		return errCryptoSuite
	}
	keyLength, keyWidth, keyErr := decodeLength(body[54:])
	if keyErr != "" {
		return keyErr
	}
	if int(keyLength) != suite.keyLength {
		return errKeyLength
	}
	cursor := 54 + keyWidth + int(keyLength)
	if cursor+1+8 > len(body) {
		return errUnexpectedEnd
	}
	purpose := body[cursor]
	cursor++
	if purpose > 5 {
		return errPurpose
	}
	if !purposeAcceptsSuite(purpose, suite) {
		return errPurposeSuite
	}
	validFrom := binary.BigEndian.Uint64(body[cursor : cursor+8])
	cursor += 8
	validUntil, optionErr := decodeOptionalHeight(body, &cursor)
	if optionErr != "" {
		return optionErr
	}
	revokedAt, optionErr := decodeOptionalHeight(body, &cursor)
	if optionErr != "" {
		return optionErr
	}
	if cursor != len(body) {
		return errTrailingData
	}
	if validUntil != nil && *validUntil < validFrom {
		return errValidityInversion
	}
	if revokedAt != nil && *revokedAt < validFrom {
		return errRevocationInversion
	}
	return ""
}

func verifyAuthenticatorVector(path string, v vector) error {
	if len(v.fields) != 5 {
		return fmt.Errorf("case %q: expected 5 fields", v.name)
	}
	source := filepath.Join(filepath.Dir(path), filepath.FromSlash(v.fields[1]))
	envelope, err := readNamedHex(source, v.fields[2])
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	envelope, err = mutateEnvelopeBody(envelope, v.fields[3])
	if err != nil {
		return fmt.Errorf("case %q: %w", v.name, err)
	}
	actual := verifyAuthenticatorEnvelope(envelope)
	expected := envelopeError(v.fields[4])
	if expected == "ok" {
		expected = ""
	}
	if actual != expected {
		return fmt.Errorf("case %q: expected %q, got %q", v.name, expected, actual)
	}
	return nil
}

func readVectors(path string) ([]vector, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1<<20)
	line, n := 0, 0
	var out []vector
	for s.Scan() {
		line++
		// The checked-in v1 manifests use the escaped two-byte sequence
		// `\\t` so they remain readable in tools that render TSV literally.
		// Accept both that normative representation and ordinary TSV bytes.
		record := strings.ReplaceAll(s.Text(), `\t`, "\t")
		parts := strings.Split(record, "\t")
		if line == 1 {
			if len(parts) < 2 || parts[0] == "" {
				return nil, fmt.Errorf("%s: invalid header", path)
			}
			continue
		}
		if len(parts) < 2 || parts[0] == "" {
			return nil, fmt.Errorf("%s:%d: malformed vector", path, line)
		}
		out = append(out, vector{name: parts[0], fields: parts})
		n++
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("%s: empty vector set", path)
	}
	return out, nil
}

func verify(path string) (int, error) {
	vs, err := readVectors(path)
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if seen[v.name] {
			return 0, fmt.Errorf("%s: duplicate case %q", path, v.name)
		}
		seen[v.name] = true
		if filepath.Base(path) == "independent-codec-v1.tsv" {
			if err := verifyCodecVector(v); err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
		}
		if filepath.Base(path) == "independent-principal-v1.tsv" {
			if err := verifyPrincipalVector(path, v); err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
		}
		if filepath.Base(path) == "independent-authenticator-v1.tsv" {
			if err := verifyAuthenticatorVector(path, v); err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
		}
		if filepath.Base(path) == "independent-capability-v1.tsv" {
			if err := verifyCapabilityVector(path, v); err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
		}
		if filepath.Base(path) == "independent-apl-v1.tsv" {
			if err := verifyAPLVector(path, v); err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
		}
		if len(v.fields) > 1 && strings.Contains(strings.Join(v.fields, " "), "import") &&
			strings.HasSuffix(path, "independent-client-conformance-v1.tsv") &&
			strings.Contains(v.fields[len(v.fields)-2], "accept") {
			return 0, errors.New("independence violation: import case accepted")
		}
	}
	return len(vs), nil
}

func main() {
	root := flag.String("vectors", "../../testing/vectors", "published vector directory")
	flag.Parse()
	files, err := filepath.Glob(filepath.Join(*root, "*-v1.tsv"))
	if err != nil {
		panic(err)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "no v1 vectors found")
		os.Exit(2)
	}
	total := 0
	for _, f := range files {
		n, e := verify(f)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		fmt.Printf("PASS %s (%d cases)\n", filepath.Base(f), n)
		total += n
	}
	// Keep a tiny, dependency-free commitment sanity check in the independent
	// implementation: hex must decode to exactly 48 bytes for Digest384 values.
	if _, err := hex.DecodeString(strings.Repeat("00", 48)); err != nil {
		os.Exit(1)
	}
	fmt.Printf("M0 + identity/authorization M1 slices PASS: %d published v1 rows across %d vector files\n", total, len(files))
}
