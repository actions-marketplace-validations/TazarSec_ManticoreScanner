package config

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var hashPrefix = regexp.MustCompile(`^sha\d+-.+`)

func LoadIgnoreList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ignore-list file: %w", err)
	}
	defer f.Close()

	var entries []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := validateIgnoreEntry(line); err != nil {
			return nil, fmt.Errorf("ignore-list %s:%d: %w", path, lineNo, err)
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading ignore-list file: %w", err)
	}
	return entries, nil
}

func validateIgnoreEntry(line string) error {
	if hashPrefix.MatchString(line) {
		return nil
	}
	idx := strings.LastIndex(line, "@")
	if idx <= 0 || idx == len(line)-1 {
		return fmt.Errorf("invalid entry %q: must be name@version or an integrity hash (e.g. sha512-...)", line)
	}
	return nil
}
