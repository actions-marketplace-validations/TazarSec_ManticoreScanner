package npm

import (
	"os"
	"sort"
	"testing"

	"github.com/TazarSec/ManticoreScanner/pkg/parser"
)

func TestPackageLockV3_WithDev(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}

	names := packageNames(pkgs)
	sort.Strings(names)

	expected := []string{"express", "jest", "lodash"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("expected %s at position %d, got %s", name, i, names[i])
		}
	}
}

func TestPackageLockV3_WithoutDev(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: false})
	if err != nil {
		t.Fatal(err)
	}

	names := packageNames(pkgs)
	sort.Strings(names)

	expected := []string{"express", "lodash"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("expected %s at position %d, got %s", name, i, names[i])
		}
	}
}

func TestPackageLockV1_WithDev(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}

	names := packageNames(pkgs)
	sort.Strings(names)

	expected := []string{"express", "jest", "lodash"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %v", len(expected), len(names), names)
	}
}

func TestPackageLockV3_IncludeTransitive(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: true, IncludeTransitive: true})
	if err != nil {
		t.Fatal(err)
	}

	names := packageNames(pkgs)
	sort.Strings(names)

	expected := []string{"@scope/util", "body-parser", "express", "jest", "lodash"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("expected %s at position %d, got %s", name, i, names[i])
		}
	}
}

func TestPackageLockV1_WithoutDev(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: false})
	if err != nil {
		t.Fatal(err)
	}

	names := packageNames(pkgs)
	sort.Strings(names)

	expected := []string{"express", "lodash"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %v", len(expected), len(names), names)
	}
}

func TestPackageLockV1_IncludeTransitive(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: true, IncludeTransitive: true})
	if err != nil {
		t.Fatal(err)
	}

	names := packageNames(pkgs)
	sort.Strings(names)

	expected := []string{"body-parser", "express", "jest", "lodash"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d packages, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("expected %s at position %d, got %s", name, i, names[i])
		}
	}
}

func TestPackageLockV3_PopulatesIntegrity(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}

	got := integrityByName(pkgs)
	if got["lodash"] != "sha512-lodash-hash==" {
		t.Errorf("lodash integrity = %q, want sha512-lodash-hash==", got["lodash"])
	}
	if got["express"] != "sha512-express-hash==" {
		t.Errorf("express integrity = %q, want sha512-express-hash==", got["express"])
	}
}

func TestPackageLockV1_PopulatesIntegrity(t *testing.T) {
	f, err := os.Open("../../../testdata/package-lock-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageLockParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}

	got := integrityByName(pkgs)
	if got["lodash"] != "sha512-lodash-hash==" {
		t.Errorf("lodash integrity = %q, want sha512-lodash-hash==", got["lodash"])
	}
	if got["express"] != "sha512-express-hash==" {
		t.Errorf("express integrity = %q, want sha512-express-hash==", got["express"])
	}
}

func integrityByName(pkgs []parser.Package) map[string]string {
	out := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		out[p.Name] = p.Integrity
	}
	return out
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/@scope/name", "@scope/name"},
		{"node_modules/a/node_modules/@scope/name", "@scope/name"},
		{"node_modules/a/node_modules/b", "b"},
		{"", ""},
		{"something/else", ""},
	}

	for _, tt := range tests {
		result := extractPackageName(tt.input)
		if result != tt.expected {
			t.Errorf("extractPackageName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
