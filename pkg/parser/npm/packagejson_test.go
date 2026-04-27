package npm

import (
	"os"
	"sort"
	"testing"

	"github.com/TazarSec/ManticoreScanner/pkg/parser"
)

func TestPackageJSONParser_WithDev(t *testing.T) {
	f, err := os.Open("../../../testdata/package.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageJSONParser{}
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

func TestPackageJSONParser_WithoutDev(t *testing.T) {
	f, err := os.Open("../../../testdata/package.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageJSONParser{}
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

func TestPackageJSONParser_VersionsCleaned(t *testing.T) {
	f, err := os.Open("../../../testdata/package.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	p := &PackageJSONParser{}
	pkgs, err := p.Parse(f, parser.ParseOptions{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}

	for _, pkg := range pkgs {
		if pkg.Version == "" {
			t.Errorf("package %s has empty version", pkg.Name)
		}
		for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
			if len(pkg.Version) > 0 && pkg.Version[:len(prefix)] == prefix {
				t.Errorf("package %s version %q still has range prefix %q", pkg.Name, pkg.Version, prefix)
			}
		}
	}
}

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"^4.17.21", "4.17.21"},
		{"~1.2.3", "1.2.3"},
		{">=2.0.0", "2.0.0"},
		{"<=3.0.0", "3.0.0"},
		{">1.0.0", "1.0.0"},
		{"<2.0.0", "2.0.0"},
		{"=1.5.0", "1.5.0"},
		{"3.0.5", "3.0.5"},
		{" ^1.0.0 ", "1.0.0"},
		{">=1.0.0 <2.0.0", "1.0.0"},
		{"1.0.0 || 2.0.0", "1.0.0"},
		{"^1.0.0 || ^2.0.0", "1.0.0"},
	}

	for _, tt := range tests {
		got := cleanVersion(tt.input)
		if got != tt.want {
			t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPackageJSONParser_Ecosystem(t *testing.T) {
	p := &PackageJSONParser{}
	if p.Ecosystem() != "npm" {
		t.Errorf("expected npm, got %s", p.Ecosystem())
	}
}

func packageNames(pkgs []parser.Package) []string {
	names := make([]string, len(pkgs))
	for i, p := range pkgs {
		names[i] = p.Name
	}
	return names
}
