// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	atxconformance "github.com/opena2a-standards/atx-conformance"
)

// entry is one fixture of the suite with its line of the answer key.
type entry struct {
	fixture Fixture
	// data is the whole fixture file, the bytes written where {file} points.
	data []byte
	// expected is the answer key's outcome, "ACCEPT" or "REJECT[CATEGORY]".
	expected    string
	mustAccept  bool
	requirement string
	level       string
}

// suite is the fixture set and answer key built into this module version.
type suite struct {
	entries []entry
	// manifestSHA256 is the SHA-256 of MANIFEST.sha256, in hex.
	manifestSHA256 string
	// manifestMatches counts the fixtures whose SHA-256 equals their line in
	// MANIFEST.sha256.
	manifestMatches int
}

// answerKey is the part of conformance.json the kit reads.
type answerKey struct {
	Requirements []struct {
		Fixture     string `json:"fixture"`
		Requirement string `json:"requirement"`
		Level       string `json:"level"`
		Expected    string `json:"expected"`
	} `json:"requirements"`
}

// loadSuite reads the embedded fixtures, conformance.json and
// MANIFEST.sha256, in fixture file name order, and fails when a fixture has
// no line in the answer key or a line names no fixture.
func loadSuite() (*suite, error) {
	return buildSuite(atxconformance.Fixtures, atxconformance.AnswerKey, atxconformance.Manifest)
}

func buildSuite(fixtures fs.FS, key, manifest []byte) (*suite, error) {
	var ak answerKey
	if err := json.Unmarshal(key, &ak); err != nil {
		return nil, fmt.Errorf("conformance.json: %w", err)
	}
	answers := make(map[string]int, len(ak.Requirements))
	for i, r := range ak.Requirements {
		if _, dup := answers[r.Fixture]; dup {
			return nil, fmt.Errorf("conformance.json names %s twice", r.Fixture)
		}
		answers[r.Fixture] = i
	}
	sums := manifestSums(manifest)

	dirEntries, err := fs.ReadDir(fixtures, "fixtures")
	if err != nil {
		return nil, err
	}
	s := &suite{manifestSHA256: sha256Hex(manifest)}
	for _, d := range dirEntries {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			continue
		}
		file := "fixtures/" + d.Name()
		data, err := fs.ReadFile(fixtures, file)
		if err != nil {
			return nil, err
		}
		i, ok := answers[file]
		if !ok {
			return nil, fmt.Errorf("conformance.json has no answer for %s", file)
		}
		delete(answers, file)
		r := ak.Requirements[i]
		var mustAccept bool
		switch {
		case r.Expected == "ACCEPT":
			mustAccept = true
		case strings.HasPrefix(r.Expected, "REJECT"):
		default:
			return nil, fmt.Errorf("conformance.json: %s expects %q, neither ACCEPT nor REJECT", file, r.Expected)
		}
		if sums[file] == sha256Hex(data) {
			s.manifestMatches++
		}
		s.entries = append(s.entries, entry{
			fixture:     Fixture{Name: d.Name(), Credential: credential(data)},
			data:        data,
			expected:    r.Expected,
			mustAccept:  mustAccept,
			requirement: r.Requirement,
			level:       r.Level,
		})
	}
	if len(answers) > 0 {
		var missing []string
		for f := range answers {
			missing = append(missing, f)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("conformance.json answers for fixtures this build does not hold: %s", strings.Join(missing, ", "))
	}
	if len(s.entries) == 0 {
		return nil, errors.New("this build holds no fixtures")
	}
	return s, nil
}

// credential is the fixture's credential JSON: the bytes of its "atx"
// member exactly as the file holds them. A fixture that is not a JSON
// object, or has no "atx" member, is sent whole.
func credential(data []byte) []byte {
	var f struct {
		ATX json.RawMessage `json:"atx"`
	}
	if json.Unmarshal(data, &f) != nil || len(f.ATX) == 0 {
		return data
	}
	return []byte(f.ATX)
}

// manifestSums reads MANIFEST.sha256 lines, "<sha256>  <path>", into a map
// from path to hex digest.
func manifestSums(manifest []byte) map[string]string {
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 {
			sums[fields[1]] = fields[0]
		}
	}
	return sums
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeFixtures writes each fixture file to dir/fixtures/<name> and sets
// its Path. It is called only when the command names {file}.
func (s *suite) writeFixtures(dir string) error {
	sub := filepath.Join(dir, "fixtures")
	if err := os.Mkdir(sub, 0o755); err != nil {
		return err
	}
	for i := range s.entries {
		e := &s.entries[i]
		p := filepath.Join(sub, e.fixture.Name)
		if err := os.WriteFile(p, e.data, 0o644); err != nil {
			return err
		}
		e.fixture.Path = p
	}
	return nil
}

// provenance is the kit version and the suite commit this binary records.
// The kit and the fixture set are one module, so the kit version is the
// module version go install or go build recorded: for `go install
// <module>/cmd/atx-verify@<commit>` a pseudo-version, whose last part is
// the first 12 hex digits of the commit. A build from a checkout records
// (devel) and, when the build recorded it, the commit in vcs.revision.
// Anything else leaves the commit "unknown".
func provenance(info *debug.BuildInfo, ok bool) (kitVersion, suiteCommit string) {
	if !ok || info == nil || info.Main.Path == "" {
		return "unknown", "unknown"
	}
	kitVersion, suiteCommit = info.Main.Version, "unknown"
	if kitVersion == "" {
		kitVersion = "unknown"
	}
	if rev := pseudoRevision(kitVersion); rev != "" {
		suiteCommit = rev
	}
	if kitVersion == "(devel)" {
		revision, modified := "", false
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if revision != "" {
			suiteCommit = revision
			if modified {
				suiteCommit += " (with uncommitted changes)"
			}
		}
	}
	return kitVersion, suiteCommit
}

// pseudoRevision is the commit a Go pseudo-version names, such as
// 7fec04045590 in v0.0.0-20261104123456-7fec04045590, or "" when v is not
// a pseudo-version.
func pseudoRevision(v string) string {
	v = strings.TrimSuffix(v, "+incompatible")
	i := strings.LastIndexByte(v, '-')
	if i < 0 {
		return ""
	}
	rev, rest := v[i+1:], v[:i]
	if len(rev) != 12 || strings.Trim(rev, "0123456789abcdef") != "" {
		return ""
	}
	if len(rest) < 14 || strings.Trim(rest[len(rest)-14:], "0123456789") != "" {
		return ""
	}
	return rev
}
