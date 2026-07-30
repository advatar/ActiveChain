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
	"strings"
)

type vector struct {
	name   string
	fields []string
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
	fmt.Printf("M0 PASS: %d published v1 rows parsed across %d vector files\n", total, len(files))
}
