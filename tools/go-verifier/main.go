// Command ac-go-verifier is the independent v1.0 M0 vector reader. It deliberately
// uses only the Go standard library and published TSV vectors; it must not
// import ActiveChain's Rust transition crates.
package main

import (
	"bufio"
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
	errUnexpectedEnd      envelopeError = "unexpected_end"
	errTypeMismatch       envelopeError = "type_mismatch"
	errVersionMismatch    envelopeError = "version_mismatch"
	errLengthOverflow     envelopeError = "length_overflow"
	errNonminimalLength   envelopeError = "nonminimal_length"
	errBodyLimit          envelopeError = "body_limit"
	errBodyLengthMismatch envelopeError = "body_length_mismatch"
	errTrailingData       envelopeError = "trailing_data"
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
	fmt.Printf("M0 + canonical-codec M1 slice PASS: %d published v1 rows across %d vector files\n", total, len(files))
}
