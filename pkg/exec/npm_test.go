package exec

import (
	"path/filepath"
	"testing"
)

func TestNPMName(t *testing.T) {
	npm := &NPM{}
	if got := npm.Name(); got != "npm" {
		t.Errorf("Name() = %q, want %q", got, "npm")
	}
}

func TestNPMPlan_Install(t *testing.T) {
	npm := &NPM{}
	dir := "/project"

	s := npm.Plan([]string{"install"}, dir)
	if s == nil {
		t.Fatal("Plan() returned nil for 'install'")
	}

	wantLock := []string{"npm", "install", "--package-lock-only", "--ignore-scripts"}
	assertSliceEqual(t, "LockfileCmd", s.LockfileCmd, wantLock)

	wantInstall := []string{"npm", "install"}
	assertSliceEqual(t, "InstallCmd", s.InstallCmd, wantInstall)

	wantPath := filepath.Join(dir, "package-lock.json")
	if s.LockfilePath != wantPath {
		t.Errorf("LockfilePath = %q, want %q", s.LockfilePath, wantPath)
	}
}

func TestNPMPlan_InstallWithPackages(t *testing.T) {
	npm := &NPM{}
	dir := "/project"

	s := npm.Plan([]string{"install", "lodash", "@types/node"}, dir)
	if s == nil {
		t.Fatal("Plan() returned nil for 'install lodash @types/node'")
	}

	wantLock := []string{"npm", "install", "--package-lock-only", "--ignore-scripts", "lodash", "@types/node"}
	assertSliceEqual(t, "LockfileCmd", s.LockfileCmd, wantLock)

	wantInstall := []string{"npm", "install", "lodash", "@types/node"}
	assertSliceEqual(t, "InstallCmd", s.InstallCmd, wantInstall)
}

func TestNPMPlan_ShortAlias(t *testing.T) {
	npm := &NPM{}
	dir := "/project"

	s := npm.Plan([]string{"i"}, dir)
	if s == nil {
		t.Fatal("Plan() returned nil for 'i'")
	}

	wantLock := []string{"npm", "i", "--package-lock-only", "--ignore-scripts"}
	assertSliceEqual(t, "LockfileCmd", s.LockfileCmd, wantLock)

	wantInstall := []string{"npm", "i"}
	assertSliceEqual(t, "InstallCmd", s.InstallCmd, wantInstall)
}

func TestNPMPlan_Add(t *testing.T) {
	npm := &NPM{}
	dir := "/project"

	s := npm.Plan([]string{"add", "express"}, dir)
	if s == nil {
		t.Fatal("Plan() returned nil for 'add express'")
	}

	wantLock := []string{"npm", "add", "--package-lock-only", "--ignore-scripts", "express"}
	assertSliceEqual(t, "LockfileCmd", s.LockfileCmd, wantLock)

	wantInstall := []string{"npm", "add", "express"}
	assertSliceEqual(t, "InstallCmd", s.InstallCmd, wantInstall)
}

func TestNPMPlan_CI(t *testing.T) {
	npm := &NPM{}
	dir := "/project"

	s := npm.Plan([]string{"ci"}, dir)
	if s == nil {
		t.Fatal("Plan() returned nil for 'ci'")
	}

	if s.LockfileCmd != nil {
		t.Errorf("LockfileCmd = %v, want nil (ci uses existing lockfile)", s.LockfileCmd)
	}

	wantInstall := []string{"npm", "ci"}
	assertSliceEqual(t, "InstallCmd", s.InstallCmd, wantInstall)

	wantPath := filepath.Join(dir, "package-lock.json")
	if s.LockfilePath != wantPath {
		t.Errorf("LockfilePath = %q, want %q", s.LockfilePath, wantPath)
	}
}

func TestNPMPlan_NonInstallCommand(t *testing.T) {
	npm := &NPM{}
	dir := "/project"

	for _, cmd := range []string{"run", "test", "start", "build", "publish"} {
		s := npm.Plan([]string{cmd}, dir)
		if s != nil {
			t.Errorf("Plan(%q) = %+v, want nil (not an install command)", cmd, s)
		}
	}
}

func TestNPMPlan_EmptyArgs(t *testing.T) {
	npm := &NPM{}
	s := npm.Plan([]string{}, "/project")
	if s != nil {
		t.Errorf("Plan(empty) = %+v, want nil", s)
	}
}

func assertSliceEqual(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s length = %d, want %d\n  got:  %v\n  want: %v", name, len(got), len(want), got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q\n  got:  %v\n  want: %v", name, i, got[i], want[i], got, want)
			return
		}
	}
}
