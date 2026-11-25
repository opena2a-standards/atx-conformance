// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	atxconformance "github.com/opena2a-standards/atx-conformance"
)

// TestEmbeddedAnswerKeyAndManifestAreTheFilesOnDisk holds the answer key
// and the manifest the module root embeds (answerkey.go) to conformance.json
// and MANIFEST.sha256 on disk, in the form
// TestEmbeddedFixturesAreTheFixtureDirectory holds the fixtures.
func TestEmbeddedAnswerKeyAndManifestAreTheFilesOnDisk(t *testing.T) {
	for name, embedded := range map[string][]byte{
		"conformance.json": atxconformance.AnswerKey,
		"MANIFEST.sha256":  atxconformance.Manifest,
	} {
		disk, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatal(err)
		}
		if len(disk) == 0 {
			t.Fatalf("%s is empty on disk; refusing to pass vacuously", name)
		}
		if !bytes.Equal(embedded, disk) {
			t.Errorf("the embedded %s differs from the file on disk", name)
		}
	}
}

// TestCredentialIsTheATXMemberAsWritten checks that the bytes sent on stdin
// are each fixture's "atx" member exactly as the file holds it.
func TestCredentialIsTheATXMemberAsWritten(t *testing.T) {
	s, err := loadSuite()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range s.entries {
		var f struct {
			ATX json.RawMessage `json:"atx"`
		}
		if err := json.Unmarshal(e.data, &f); err != nil {
			t.Fatalf("%s: %v", e.fixture.Name, err)
		}
		if len(f.ATX) == 0 || !bytes.Equal(e.fixture.Credential, f.ATX) || !bytes.Contains(e.data, e.fixture.Credential) {
			t.Errorf("%s: the credential is not the atx member as written", e.fixture.Name)
		}
	}
	if got := credential([]byte(`[1, 2]`)); string(got) != `[1, 2]` {
		t.Errorf("a fixture that is not an object is sent whole, got %q", got)
	}
}

func TestBuildSuiteRefusesAKeyThatDoesNotMatchTheFixtures(t *testing.T) {
	fixtures := fstest.MapFS{
		"fixtures/a.json": {Data: []byte(`{"atx":{}}`)},
		"fixtures/b.json": {Data: []byte(`{"atx":{}}`)},
	}
	cases := map[string]string{
		`{"requirements":[{"fixture":"fixtures/a.json","expected":"ACCEPT"}]}`:                                                                                                        "no answer for fixtures/b.json",
		`{"requirements":[{"fixture":"fixtures/a.json","expected":"ACCEPT"},{"fixture":"fixtures/b.json","expected":"REJECT[X]"},{"fixture":"fixtures/c.json","expected":"ACCEPT"}]}`: "fixtures/c.json",
		`{"requirements":[{"fixture":"fixtures/a.json","expected":"ACCEPT"},{"fixture":"fixtures/b.json","expected":"MAYBE"}]}`:                                                       "neither ACCEPT nor REJECT",
		`{"requirements":[{"fixture":"fixtures/a.json","expected":"ACCEPT"},{"fixture":"fixtures/a.json","expected":"ACCEPT"}]}`:                                                      "twice",
		`not json`: "conformance.json",
	}
	for key, want := range cases {
		if _, err := buildSuite(fixtures, []byte(key), nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("key %s: err = %v, want one naming %q", key, err, want)
		}
	}
	s, err := buildSuite(fixtures, []byte(`{"requirements":[{"fixture":"fixtures/b.json","expected":"REJECT[X]"},{"fixture":"fixtures/a.json","expected":"ACCEPT"}]}`), nil)
	if err != nil || len(s.entries) != 2 || s.entries[0].fixture.Name != "a.json" || !s.entries[0].mustAccept || s.entries[1].mustAccept || s.manifestMatches != 0 {
		t.Errorf("buildSuite = %+v, %v", s, err)
	}
}
