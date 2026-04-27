package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/TazarSec/ManticoreScanner/pkg/parser"
)

type lockfile struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string]lockfilePackage   `json:"packages"`
	Dependencies    map[string]lockfileLegacyDep `json:"dependencies"`
}

type lockfilePackage struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Integrity       string            `json:"integrity"`
	Dev             bool              `json:"dev"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type lockfileLegacyDep struct {
	Version      string                       `json:"version"`
	Integrity    string                       `json:"integrity"`
	Dev          bool                         `json:"dev"`
	Dependencies map[string]lockfileLegacyDep `json:"dependencies"`
}

type PackageLockParser struct{}

func (p *PackageLockParser) Ecosystem() string { return "npm" }

func (p *PackageLockParser) Parse(r io.Reader, opts parser.ParseOptions) ([]parser.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	switch {
	case lf.LockfileVersion >= 2 && lf.Packages != nil:
		return parseV2V3(lf.Packages, opts)
	case lf.Dependencies != nil:
		return parseV1(lf.Dependencies, opts)
	default:
		return nil, fmt.Errorf("unsupported lockfile version %d or empty lockfile", lf.LockfileVersion)
	}
}

func parseRootPackages(packages map[string]lockfilePackage) (map[string]struct{}, error) {
	var rootPackages = make(map[string]struct{}, 64)
	if pkg, ok := packages[""]; ok {
		for k := range pkg.Dependencies {
			rootPackages[k] = struct{}{}
		}
		for k := range pkg.DevDependencies {
			rootPackages[k] = struct{}{}
		}
	} else {
		return rootPackages, errors.New("package-json does not contain root dependency")
	}
	return rootPackages, nil
}

func parseV2V3(packages map[string]lockfilePackage, opts parser.ParseOptions) ([]parser.Package, error) {
	seen := make(map[string]bool)
	var result []parser.Package

	var rootPackages map[string]struct{}
	if !opts.IncludeTransitive {
		var err error
		rootPackages, err = parseRootPackages(packages)
		if err != nil {
			return result, err
		}
	}

	for key, pkg := range packages {
		if pkg.Dev && !opts.IncludeDev {
			continue
		}

		name := extractPackageName(key)
		if name == "" {
			continue
		}
		if !opts.IncludeTransitive {
			if _, ok := rootPackages[name]; !ok {
				continue
			}
		}

		dedup := name + "@" + pkg.Version
		if seen[dedup] {
			continue
		}
		seen[dedup] = true

		result = append(result, parser.Package{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "npm",
			Integrity: pkg.Integrity,
		})
	}

	return result, nil
}

func extractPackageName(key string) string {
	const prefix = "node_modules/"
	idx := strings.LastIndex(key, prefix)
	if idx == -1 {
		return ""
	}
	return key[idx+len(prefix):]
}

func parseV1(deps map[string]lockfileLegacyDep, opts parser.ParseOptions) ([]parser.Package, error) {
	seen := make(map[string]bool)
	var result []parser.Package
	walkV1(deps, opts, seen, &result)
	return result, nil
}

func walkV1(deps map[string]lockfileLegacyDep, opts parser.ParseOptions, seen map[string]bool, out *[]parser.Package) {
	for name, dep := range deps {
		if dep.Dev && !opts.IncludeDev {
			continue
		}

		dedup := name + "@" + dep.Version
		if !seen[dedup] {
			seen[dedup] = true
			*out = append(*out, parser.Package{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
				Integrity: dep.Integrity,
			})
		}

		if opts.IncludeTransitive && len(dep.Dependencies) > 0 {
			walkV1(dep.Dependencies, opts, seen, out)
		}
	}
}
