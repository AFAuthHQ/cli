// Package specvectors locates and loads the AFAuthHQ/spec conformance
// vectors vendored under <repo>/testdata/spec-vectors. The package is
// imported by tests across internal/proto, internal/signing,
// internal/identity, and future G2+ packages so every test reads from
// a single physical location refreshed by `make sync-vectors`.
//
// Path resolution is via runtime.Caller(0) so the vectors are found
// regardless of where `go test` is invoked from. The vectors directory
// is never embedded into the production binary — these helpers run at
// test time only.
package specvectors

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Root returns the absolute path to <repo>/testdata/spec-vectors.
// Callers should join further path components rather than hardcoding
// this layout.
func Root() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "spec-vectors"))
}

// LoadAll returns the contents of every *.json file in the named
// subdirectory of the spec-vectors tree, keyed by base name without
// extension. Names are sorted for stable test output.
func LoadAll(subdir string) (map[string][]byte, []string, error) {
	dir := filepath.Join(Root(), subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("specvectors: read %s: %w", dir, err)
	}
	out := make(map[string][]byte)
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Skip internal generator scripts.
		if strings.HasPrefix(e.Name(), "_") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, nil, fmt.Errorf("specvectors: read %s: %w", e.Name(), err)
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		out[name] = data
		names = append(names, name)
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("specvectors: no JSON files found in %s (has `make sync-vectors` been run?)", dir)
	}
	sort.Strings(names)
	return out, names, nil
}

// LoadFile returns the contents of a single named file under the
// spec-vectors root. The path is joined to Root().
func LoadFile(relPath string) ([]byte, error) {
	full := filepath.Join(Root(), relPath)
	return os.ReadFile(full)
}
