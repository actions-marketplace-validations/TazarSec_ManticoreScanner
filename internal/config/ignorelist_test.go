package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadIgnoreList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ignore.txt")
	contents := "" +
		"# top-level comment\n" +
		"lodash@4.17.21\n" +
		"  express@4.18.2  \n" +
		"\n" +
		"# section divider\n" +
		"@scope/pkg@1.2.3\n" +
		"sha512-abcdef==\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := LoadIgnoreList(path)
	if err != nil {
		t.Fatalf("LoadIgnoreList: %v", err)
	}
	want := []string{"lodash@4.17.21", "express@4.18.2", "@scope/pkg@1.2.3", "sha512-abcdef=="}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLoadIgnoreListMissingFile(t *testing.T) {
	_, err := LoadIgnoreList(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadIgnoreListEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := LoadIgnoreList(path)
	if err != nil {
		t.Fatalf("LoadIgnoreList: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no entries, got %v", got)
	}
}

func TestLoadIgnoreListRejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"bare name", "lodash\n"},
		{"bare scoped name", "@scope/pkg\n"},
		{"trailing at", "lodash@\n"},
		{"empty hash body", "sha512-\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ignore.txt")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := LoadIgnoreList(path)
			if err == nil {
				t.Fatalf("expected error for content %q", tc.content)
			}
			if !strings.Contains(err.Error(), "must be name@version") {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}
