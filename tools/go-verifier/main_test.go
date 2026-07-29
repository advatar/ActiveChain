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
