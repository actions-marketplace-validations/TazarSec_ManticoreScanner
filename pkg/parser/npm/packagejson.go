package npm

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/TazarSec/ManticoreScanner/pkg/parser"
)

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	// Compound ranges (">=1.0.0 <2.0.0") and unions ("1.0.0 || 2.0.0") get
	// reduced to the first token so we send a single resolvable version
	// instead of a constraint string the backend cannot match.
	if idx := strings.IndexAny(v, " \t"); idx >= 0 {
		v = v[:idx]
	}
	for _, prefix := range []string{">=", "<=", "^", "~", ">", "<", "="} {
		if strings.HasPrefix(v, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(v, prefix))
		}
	}
	return v
}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type PackageJSONParser struct{}

func (p *PackageJSONParser) Ecosystem() string { return "npm" }

func (p *PackageJSONParser) Parse(r io.Reader, opts parser.ParseOptions) ([]parser.Package, error) {
	var pkg packageJSON
	if err := json.NewDecoder(r).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	seen := make(map[string]bool)
	var packages []parser.Package

	for name, version := range pkg.Dependencies {
		version = cleanVersion(version)
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		packages = append(packages, parser.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}

	if opts.IncludeDev {
		for name, version := range pkg.DevDependencies {
			version = cleanVersion(version)
			key := name + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true
			packages = append(packages, parser.Package{
				Name:      name,
				Version:   version,
				Ecosystem: "npm",
			})
		}
	}

	return packages, nil
}
