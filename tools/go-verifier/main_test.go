package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVectorsRejectMalformedAndDuplicateCases(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "bad.tsv")
	if err := os.WriteFile(p, []byte("case\tclient_behavior\texpected\treason\na\tb\taccept\tx\na\tb\treject\ty\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(p); err == nil {
		t.Fatal("duplicate case accepted")
	}
}

func TestVectorsAcceptPublishedConformanceFile(t *testing.T) {
	n, err := verify("../../testing/vectors/independent-client-conformance-v1.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Fatalf("expected conformance cases, got %d", n)
	}
}

func TestVectorsAcceptLiteralTabManifest(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "literal.tsv")
	contents := "case\\tclient_behavior\\texpected\\treason\ncase_a\\tdecode\\taccept\\tstable\n"
	if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := verify(p); err != nil || n != 1 {
		t.Fatalf("literal-tab manifest: n=%d err=%v", n, err)
	}
}

func TestIndependentCodecSemanticVectors(t *testing.T) {
	n, err := verify("../../testing/vectors/independent-codec-v1.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if n != 12 {
		t.Fatalf("expected 12 semantic codec cases, got %d", n)
	}
}

func TestCodecRejectsNonminimalLengthAndTrailingBytes(t *testing.T) {
	if _, got := inspectEnvelope([]byte{0x12, 0x34, 0, 1, 0x81, 0, 0xaa}, 0x1234, 1, 1); got != errNonminimalLength {
		t.Fatalf("non-minimal length: got %q", got)
	}
	if _, got := inspectEnvelope([]byte{0x12, 0x34, 0, 1, 1, 0xaa, 0xbb}, 0x1234, 1, 1); got != errTrailingData {
		t.Fatalf("trailing data: got %q", got)
	}
}

func TestIndependentPrincipalSemanticVectors(t *testing.T) {
	n, err := verify("../../testing/vectors/independent-principal-v1.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("expected 6 semantic principal cases, got %d", n)
	}
}
