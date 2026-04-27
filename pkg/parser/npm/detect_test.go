package npm

import (
	"testing"

	"github.com/TazarSec/ManticoreScanner/pkg/parser"
)

func TestDetectAndParse_Directory(t *testing.T) {
	// testdata directory has both package.json and package-lock-v3.json but
	// it does not have a file named exactly "package-lock.json", so it should
	// fall back to package.json.
	pkgs, file, err := DetectAndParse("../../../testdata", parser.ParseOptions{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}
	if file == "" {
		t.Fatal("expected a file path")
	}
	if len(pkgs) == 0 {
		t.Fatal("expected some packages")
	}
}

func TestDetectAndParse_ExplicitFile(t *testing.T) {
	pkgs, file, err := DetectAndParse("../../../testdata/package-lock-v3.json", parser.ParseOptions{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}
	if file != "../../../testdata/package-lock-v3.json" {
		t.Errorf("expected explicit file path, got %s", file)
	}
	if len(pkgs) != 3 {
		t.Errorf("expected 3 packages, got %d", len(pkgs))
	}
}

func TestDetectAndParse_InvalidPath(t *testing.T) {
	_, _, err := DetectAndParse("/nonexistent", parser.ParseOptions{})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}
