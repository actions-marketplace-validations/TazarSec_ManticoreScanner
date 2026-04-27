package exec

import "testing"

func TestDetect_NPM(t *testing.T) {
	pm := Detect("npm")
	if pm == nil {
		t.Fatal("Detect(\"npm\") returned nil")
	}
	if pm.Name() != "npm" {
		t.Errorf("Name() = %q, want %q", pm.Name(), "npm")
	}
}

func TestDetect_NPMFullPath(t *testing.T) {
	pm := Detect("/usr/local/bin/npm")
	if pm == nil {
		t.Fatal("Detect(\"/usr/local/bin/npm\") returned nil")
	}
	if pm.Name() != "npm" {
		t.Errorf("Name() = %q, want %q", pm.Name(), "npm")
	}
}

func TestDetect_Unsupported(t *testing.T) {
	for _, cmd := range []string{"yarn", "pnpm", "cargo", "pip", "unknown"} {
		pm := Detect(cmd)
		if pm != nil {
			t.Errorf("Detect(%q) = %v, want nil", cmd, pm)
		}
	}
}
