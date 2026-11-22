package main

// This file reads a fixture and computes the bytes its native signatures
// cover. The types ATCSignature, ATCBehavioralProfile, ATCScanSummary, ATX,
// tbsScanSummaryV11, tbsBehavioralProfileV11 and tbsV11, and the functions
// canonicalPayload, canonicalPayloadV11 and projectDeclaredPurposeV11, are
// copied from scripts/generate-fixtures/main.go, the program that signed
// every fixture. That program is a separate module's package main, so it
// cannot be imported. The code is unchanged except that canonicalPayloadV11
// returns its errors instead of panicking; the comments are shortened.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/gowebpki/jcs"
)

// atcVersion and atcVersionV11 are the two native credential versions. A
// "1.0" credential signs the legacy pipe-delimited string of canonicalPayload;
// a "1.1" credential signs JCS(TBS), canonicalPayloadV11.
const atcVersion = "1.0"
const atcVersionV11 = "1.1"

// ATCSignature is one entry of a native credential's signatures array.
type ATCSignature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// ATCBehavioralProfile is the native behavioralProfile object.
type ATCBehavioralProfile struct {
	Checksum        string    `json:"checksum"`
	GeneratedAt     time.Time `json:"generatedAt"`
	ObservationDays int       `json:"observationDays"`
}

// ATCScanSummary is the native scanSummary object.
type ATCScanSummary struct {
	HMA              string `json:"hma"`
	CriticalFindings int    `json:"criticalFindings"`
	HighFindings     int    `json:"highFindings"`
	Secretless       string `json:"secretless"`
	CryptoServe      string `json:"cryptoServe"`
	OASBLevel        string `json:"oasbLevel"`
}

// ATX is the native credential as the conformance suite serializes it.
type ATX struct {
	ID                   string                `json:"id"`
	ATCVersion           string                `json:"atcVersion"`
	AgentID              string                `json:"agentId"`
	AgentDID             string                `json:"agentDid"`
	Publisher            string                `json:"publisher"`
	PublisherDID         string                `json:"publisherDid,omitempty"`
	Version              string                `json:"version"`
	ContentHash          string                `json:"contentHash"`
	BuildAttestation     string                `json:"buildAttestation,omitempty"`
	TransparencyLogIndex *int64                `json:"transparencyLogIndex,omitempty"`
	Capabilities         []string              `json:"capabilities"`
	DeclaredPurpose      json.RawMessage       `json:"declaredPurpose,omitempty"`
	BehavioralProfile    *ATCBehavioralProfile `json:"behavioralProfile,omitempty"`
	ScanSummary          *ATCScanSummary       `json:"scanSummary"`
	TrustScore           float64               `json:"trustScore"`
	TrustLevel           int                   `json:"trustLevel"`
	IssuedAt             time.Time             `json:"issuedAt"`
	ExpiresAt            time.Time             `json:"expiresAt"`
	IssuerDID            string                `json:"issuerDid"`
	IssuerChain          []string              `json:"issuerChain"`
	Signatures           []ATCSignature        `json:"signatures"`
	Revoked              bool                  `json:"revoked"`
	RevokedAt            *time.Time            `json:"revokedAt,omitempty"`
	RevocationReason     string                `json:"revocationReason,omitempty"`
	CreatedAt            time.Time             `json:"createdAt"`
}

// canonicalPayload returns the bytes an ATX v1.0 signature covers: the
// eleven-field pipe-delimited string.
func canonicalPayload(a *ATX) []byte {
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%.6f|%s|%s|%s",
		a.AgentID,
		a.AgentDID,
		a.Version,
		a.ContentHash,
		a.BuildAttestation,
		a.IssuerDID,
		a.TrustLevel,
		a.TrustScore,
		a.IssuedAt.UTC().Format(time.RFC3339),
		a.ExpiresAt.UTC().Format(time.RFC3339),
		atcVersion,
	)
	return []byte(canonical)
}

// tbsV11 and friends are the ATX v1.1 to-be-signed projection (atx-spec
// core.md §1.3a.2). JCS sorts member names, so field order is irrelevant.
type tbsScanSummaryV11 struct {
	HMA              string `json:"hma"`
	CriticalFindings int    `json:"criticalFindings"`
	HighFindings     int    `json:"highFindings"`
	Secretless       string `json:"secretless"`
	CryptoServe      string `json:"cryptoServe"`
	OASBLevel        string `json:"oasbLevel"`
}

type tbsBehavioralProfileV11 struct {
	Checksum        string `json:"checksum"`
	GeneratedAt     string `json:"generatedAt"`
	ObservationDays int    `json:"observationDays"`
}

type tbsV11 struct {
	ATCVersion        string            `json:"atcVersion"`
	AgentID           string            `json:"agentId"`
	AgentDID          string            `json:"agentDid"`
	Publisher         string            `json:"publisher"`
	PublisherDID      string            `json:"publisherDid"`
	Version           string            `json:"version"`
	ContentHash       string            `json:"contentHash"`
	BuildAttestation  string            `json:"buildAttestation"`
	Capabilities      []string          `json:"capabilities"`
	DeclaredPurpose   json.RawMessage   `json:"declaredPurpose,omitempty"`
	BehavioralProfile json.RawMessage   `json:"behavioralProfile"`
	ScanSummary       tbsScanSummaryV11 `json:"scanSummary"`
	TrustScore        string            `json:"trustScore"`
	TrustLevel        int               `json:"trustLevel"`
	IssuedAt          string            `json:"issuedAt"`
	ExpiresAt         string            `json:"expiresAt"`
	IssuerDID         string            `json:"issuerDid"`
	IssuerChain       []string          `json:"issuerChain"`
}

// canonicalPayloadV11 projects an ATX into the v1.1 TBS and returns JCS(TBS).
func canonicalPayloadV11(a *ATX) ([]byte, error) {
	caps := a.Capabilities
	if caps == nil {
		caps = []string{}
	}
	chain := a.IssuerChain
	if chain == nil {
		chain = []string{}
	}
	var ss tbsScanSummaryV11
	if a.ScanSummary != nil {
		ss = tbsScanSummaryV11{
			HMA: a.ScanSummary.HMA, CriticalFindings: a.ScanSummary.CriticalFindings,
			HighFindings: a.ScanSummary.HighFindings, Secretless: a.ScanSummary.Secretless,
			CryptoServe: a.ScanSummary.CryptoServe, OASBLevel: a.ScanSummary.OASBLevel,
		}
	}
	bp := json.RawMessage("null")
	if a.BehavioralProfile != nil {
		bpObj := tbsBehavioralProfileV11{
			Checksum:        a.BehavioralProfile.Checksum,
			GeneratedAt:     a.BehavioralProfile.GeneratedAt.UTC().Format(time.RFC3339),
			ObservationDays: a.BehavioralProfile.ObservationDays,
		}
		b, err := json.Marshal(&bpObj)
		if err != nil {
			return nil, err
		}
		bp = b
	}
	tbs := tbsV11{
		ATCVersion: a.ATCVersion, AgentID: a.AgentID, AgentDID: a.AgentDID,
		Publisher: a.Publisher, PublisherDID: a.PublisherDID, Version: a.Version,
		ContentHash: a.ContentHash, BuildAttestation: a.BuildAttestation,
		Capabilities: caps, DeclaredPurpose: projectDeclaredPurposeV11(a.DeclaredPurpose),
		BehavioralProfile: bp, ScanSummary: ss,
		TrustScore: fmt.Sprintf("%.6f", a.TrustScore), TrustLevel: a.TrustLevel,
		IssuedAt: a.IssuedAt.UTC().Format(time.RFC3339), ExpiresAt: a.ExpiresAt.UTC().Format(time.RFC3339),
		IssuerDID: a.IssuerDID, IssuerChain: chain,
	}
	raw, err := json.Marshal(&tbs)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// projectDeclaredPurposeV11 implements the presence-based rule for the
// optional declaredPurpose TBS member (atx-spec §1.3a.2 rule 5): absent,
// null, or any serialization of the empty object normalizes to nil, so
// omitempty drops it from the TBS; any other value passes through verbatim.
func projectDeclaredPurposeV11(raw json.RawMessage) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj) == 0 {
		return nil
	}
	return raw
}

// nativeSignedBytes returns the bytes every native signature of a covers:
// for atcVersion "1.1" the JCS bytes of the TBS projection, for "1.0" the
// legacy string.
func nativeSignedBytes(a *ATX) ([]byte, error) {
	switch a.ATCVersion {
	case atcVersionV11:
		return canonicalPayloadV11(a)
	case atcVersion:
		return canonicalPayload(a), nil
	default:
		return nil, fmt.Errorf("atx: atcVersion %q has no native signed bytes (want %q or %q)", a.ATCVersion, atcVersion, atcVersionV11)
	}
}

// keypairRef is one entry of a fixture's keypairRefs: the public half of a
// test key, and the vector file that holds its seed.
type keypairRef struct {
	Path         string
	Algorithm    string
	PublicKeyHex string
	KeyID        string
}

// fixture is one conformance fixture as the exporter reads it.
type fixture struct {
	// native holds the atx object decoded into the type the generator signed.
	native ATX
	// members holds the same atx object member by member, numbers as written.
	members map[string]any
	refs    []keypairRef
	// root is the directory the keypairRefs' vector paths are relative to:
	// the parent of the fixture's own directory.
	root string
}

// readFixture reads the fixture file at path. It refuses an atx object
// that RFC 8785 cannot canonicalize (a duplicate member name, or a number
// outside the IEEE 754 double range), and one with a member whose name
// differs from an ATX member name only by letter case, because a decoder
// that folds case would read a different credential than one that does not.
func readFixture(path string) (*fixture, error) {
	// The path is the operator's own argument; Clean only normalizes it.
	clean := filepath.Clean(path)
	raw, err := os.ReadFile(clean)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("%s: not a fixture: %w", path, err)
	}
	atxRaw, ok := top["atx"]
	if !ok {
		return nil, fmt.Errorf("%s: not a fixture: no atx member", path)
	}
	if _, err := jcs.Transform(atxRaw); err != nil {
		return nil, fmt.Errorf("%s: atx cannot be canonicalized (RFC 8785): %w", path, err)
	}
	members, err := decodeObject(atxRaw)
	if err != nil {
		return nil, fmt.Errorf("%s: atx: %w", path, err)
	}
	if err := checkMemberCase(members); err != nil {
		return nil, fmt.Errorf("%s: atx: %w", path, err)
	}
	f := &fixture{members: members, root: filepath.Join(filepath.Dir(clean), "..")}
	if err := json.Unmarshal(atxRaw, &f.native); err != nil {
		return nil, fmt.Errorf("%s: atx: %w", path, err)
	}
	if f.refs, err = decodeKeypairRefs(top["keypairRefs"]); err != nil {
		return nil, fmt.Errorf("%s: keypairRefs: %w", path, err)
	}
	return f, nil
}

// decodeObject decodes a JSON object member by member, keeping numbers as
// written (json.Number).
func decodeObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	return obj, nil
}

// checkMemberCase refuses a member of the atx object, or of its
// behavioralProfile, scanSummary or signatures entries, whose name equals an
// ATX member name under Unicode case folding without being equal to it.
// encoding/json matches member names that way, so without this check the
// native bytes could be computed from a different member than the one the
// credential carries.
func checkMemberCase(atx map[string]any) error {
	if err := checkObjectCase("", atx, reflect.TypeOf(ATX{})); err != nil {
		return err
	}
	if bp, ok := atx["behavioralProfile"].(map[string]any); ok {
		if err := checkObjectCase("behavioralProfile: ", bp, reflect.TypeOf(ATCBehavioralProfile{})); err != nil {
			return err
		}
	}
	if ss, ok := atx["scanSummary"].(map[string]any); ok {
		if err := checkObjectCase("scanSummary: ", ss, reflect.TypeOf(ATCScanSummary{})); err != nil {
			return err
		}
	}
	if sigs, ok := atx["signatures"].([]any); ok {
		for i, s := range sigs {
			if obj, ok := s.(map[string]any); ok {
				if err := checkObjectCase(fmt.Sprintf("signatures[%d]: ", i), obj, reflect.TypeOf(ATCSignature{})); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkObjectCase(where string, obj map[string]any, t reflect.Type) error {
	for _, k := range sortedNames(obj) {
		for _, field := range jsonNames(t) {
			if k != field && strings.EqualFold(k, field) {
				return fmt.Errorf("%smember %q differs from member %q only by letter case", where, k, field)
			}
		}
	}
	return nil
}

// uncoveredMember returns a member that the credential would carry inside
// behavioralProfile or scanSummary but that the v1.1 TBS projection leaves
// out. A native signature cannot cover such a member, so it verifies whether
// or not the issuer wrote it. Only a "1.1" credential is checked: a "1.0"
// signature covers none of these objects.
func uncoveredMember(a *ATX, atx map[string]any) (string, bool) {
	if a.ATCVersion != atcVersionV11 {
		return "", false
	}
	if bp, ok := atx["behavioralProfile"].(map[string]any); ok {
		if name, found := memberOutside(bp, reflect.TypeOf(tbsBehavioralProfileV11{})); found {
			return "behavioralProfile." + name, true
		}
	}
	if ss, ok := atx["scanSummary"].(map[string]any); ok {
		if name, found := memberOutside(ss, reflect.TypeOf(tbsScanSummaryV11{})); found {
			return "scanSummary." + name, true
		}
	}
	return "", false
}

func memberOutside(obj map[string]any, t reflect.Type) (string, bool) {
	for _, k := range sortedNames(obj) {
		covered := false
		for _, field := range jsonNames(t) {
			covered = covered || k == field
		}
		if !covered {
			return k, true
		}
	}
	return "", false
}

// maxExactInteger is 2^53-1, the largest magnitude of an integer in the
// I-JSON exact range (RFC 7493 §2.2). jcs.Transform reads each number as an
// IEEE 754 double (RFC 8785 §3.2.2.3), which holds every integer in that
// range and writes it as its decimal digits. Outside it a double does not
// hold every integer: 9007199254740993 is written as 9007199254740992.
const maxExactInteger int64 = 1<<53 - 1

// uncoveredNumber names the first number of a "1.1" credential's TBS that
// JCS(TBS) does not hold as the credential writes it, so that a native
// signature verifies whether the credential writes that number or another:
// an integer whose magnitude is above maxExactInteger, or a declaredPurpose
// number written with a fraction or an exponent part, which jcs.Transform
// writes as the double nearest it (1e3, 1000.0 and 1E3 as 1000). The rule
// and its order are those of integerOutsideExactRangeV11 in
// verifiers/go/verifier/verify.go, by which the reference verifier rejects
// such a credential before it canonicalizes:
// behavioralProfile.observationDays, the numbers of declaredPurpose in the
// order written, scanSummary.criticalFindings, scanSummary.highFindings,
// trustLevel. where is the member, literal the number (as written in
// declaredPurpose, in decimal digits elsewhere), and fractionOrExponent is
// set for a number written with a fraction or an exponent part. where is ""
// when the TBS holds no such number, and for a "1.0" credential, whose
// signed string writes trustLevel digit for digit and holds none of the
// other members. readFixture has refused, before this is called, an atx
// object holding a number outside the IEEE 754 double range or an integer
// member outside the int range, so the rule reads neither.
func uncoveredNumber(a *ATX) (where, literal string, fractionOrExponent bool) {
	if a.ATCVersion != atcVersionV11 {
		return "", "", false
	}
	exact := func(n int64) bool { return -maxExactInteger <= n && n <= maxExactInteger }
	if bp := a.BehavioralProfile; bp != nil && !exact(int64(bp.ObservationDays)) {
		return "behavioralProfile.observationDays", strconv.Itoa(bp.ObservationDays), false
	}
	for _, number := range purposeNumbersV11(a.DeclaredPurpose) {
		// The form is decided from the number as written, whatever its value.
		if strings.ContainsAny(string(number), ".eE") {
			return "declaredPurpose", string(number), true
		}
		// A JSON integer that ParseInt refuses is outside the int64 range.
		if n, err := strconv.ParseInt(string(number), 10, 64); err != nil || !exact(n) {
			return "declaredPurpose", string(number), false
		}
	}
	if ss := a.ScanSummary; ss != nil {
		if !exact(int64(ss.CriticalFindings)) {
			return "scanSummary.criticalFindings", strconv.Itoa(ss.CriticalFindings), false
		}
		if !exact(int64(ss.HighFindings)) {
			return "scanSummary.highFindings", strconv.Itoa(ss.HighFindings), false
		}
	}
	if !exact(int64(a.TrustLevel)) {
		return "trustLevel", strconv.Itoa(a.TrustLevel), false
	}
	return "", "", false
}

// purposeNumbersV11 returns each number the declaredPurpose raw writes, as
// written and in the order written, and none when the v1.1 TBS omits
// declaredPurpose. declaredPurpose enters the TBS as written, so no typed
// decode reads these numbers.
func purposeNumbersV11(raw json.RawMessage) []json.Number {
	purpose := projectDeclaredPurposeV11(raw)
	if purpose == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(purpose))
	dec.UseNumber()
	var numbers []json.Number
	for {
		tok, err := dec.Token()
		if err != nil {
			return numbers // io.EOF: readFixture has decoded this text whole
		}
		if number, ok := tok.(json.Number); ok {
			numbers = append(numbers, number)
		}
	}
}

// jsonNames returns the JSON member names the struct type t declares.
func jsonNames(t reflect.Type) []string {
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}

func sortedNames(obj map[string]any) []string {
	names := make([]string, 0, len(obj))
	for k := range obj {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// decodeKeypairRefs reads the keypairRefs array member by member.
func decodeKeypairRefs(raw json.RawMessage) ([]keypairRef, error) {
	if raw == nil {
		return nil, nil
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	refs := make([]keypairRef, 0, len(entries))
	for _, e := range entries {
		refs = append(refs, keypairRef{
			Path:         stringMember(e, "path"),
			Algorithm:    stringMember(e, "algorithm"),
			PublicKeyHex: stringMember(e, "publicKeyHex"),
			KeyID:        stringMember(e, "keyId"),
		})
	}
	return refs, nil
}

func stringMember(obj map[string]any, name string) string {
	s, _ := obj[name].(string)
	return s
}

// refFor returns the first keypairRef whose keyId is keyID.
func (f *fixture) refFor(keyID string) (keypairRef, bool) {
	for _, r := range f.refs {
		if r.KeyID == keyID {
			return r, true
		}
	}
	return keypairRef{}, false
}

// nativeSignatureVerifies reports whether sig verifies over payload with the
// public key of the keypairRef whose keyId equals the signature's keyId. A
// signature with no such keypairRef, or with an algorithm other than the
// keypairRef's, does not verify.
func (f *fixture) nativeSignatureVerifies(sig ATCSignature, payload []byte) bool {
	ref, ok := f.refFor(sig.KeyID)
	if !ok || ref.Algorithm != sig.Algorithm {
		return false
	}
	pub, err := hex.DecodeString(ref.PublicKeyHex)
	if err != nil {
		return false
	}
	value, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return false
	}
	switch sig.Algorithm {
	case "Ed25519":
		return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), payload, value)
	case "ML-DSA-65":
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return false
		}
		return mldsa65.Verify(&pk, payload, nil, value)
	default:
		return false
	}
}

// vectorPath is the form of a keypairRef path: a JSON file directly under
// the suite's vectors directory.
var vectorPath = regexp.MustCompile(`^vectors/[A-Za-z0-9][A-Za-z0-9._-]*\.json$`)

// seed returns the 32-byte seed of the key keyID names, read from the vector
// file its keypairRef names. The vector file must name the same keyId,
// algorithm and public key as the keypairRef.
func (f *fixture) seed(keyID, algorithm string) ([]byte, keypairRef, error) {
	ref, ok := f.refFor(keyID)
	if !ok {
		return nil, ref, fmt.Errorf("no keypairRef has keyId %q", keyID)
	}
	if ref.Algorithm != algorithm {
		return nil, ref, fmt.Errorf("keypairRef %q is %q, not %q", keyID, ref.Algorithm, algorithm)
	}
	if !vectorPath.MatchString(ref.Path) {
		return nil, ref, fmt.Errorf("keypairRef %q: path %q is not a vectors/*.json file", keyID, ref.Path)
	}
	raw, err := fs.ReadFile(os.DirFS(f.root), ref.Path)
	if err != nil {
		return nil, ref, fmt.Errorf("keypairRef %q: %w", keyID, err)
	}
	vec, err := decodeObject(raw)
	if err != nil {
		return nil, ref, fmt.Errorf("%s: %w", ref.Path, err)
	}
	if stringMember(vec, "keyId") != keyID || stringMember(vec, "algorithm") != algorithm ||
		stringMember(vec, "publicKeyHex") != ref.PublicKeyHex {
		return nil, ref, fmt.Errorf("%s: keyId, algorithm or publicKeyHex differs from keypairRef %q", ref.Path, keyID)
	}
	seed, err := hex.DecodeString(stringMember(vec, "seedHex"))
	if err != nil || len(seed) != 32 {
		return nil, ref, fmt.Errorf("%s: seedHex is not 32 bytes of hex", ref.Path)
	}
	return seed, ref, nil
}

// ed25519Key returns the Ed25519 private key of keyID, derived from its
// vector seed as the fixture generator derives it, after checking that it
// yields the keypairRef's public key.
func (f *fixture) ed25519Key(keyID string) (ed25519.PrivateKey, error) {
	seed, ref, err := f.seed(keyID, "Ed25519")
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if pub, _ := priv.Public().(ed25519.PublicKey); hex.EncodeToString(pub) != ref.PublicKeyHex {
		return nil, fmt.Errorf("%s: seed does not derive the public key of keypairRef %q", ref.Path, keyID)
	}
	return priv, nil
}

// mldsa65Key returns the ML-DSA-65 private key of keyID, derived from its
// vector seed with CIRCL's deterministic key generation as the fixture
// generator derives it, after checking that it yields the keypairRef's
// public key.
func (f *fixture) mldsa65Key(keyID string) (*mldsa65.PrivateKey, error) {
	seed, ref, err := f.seed(keyID, "ML-DSA-65")
	if err != nil {
		return nil, err
	}
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)
	pub, priv := mldsa65.NewKeyFromSeed(&seedArr)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(pubBytes) != ref.PublicKeyHex {
		return nil, fmt.Errorf("%s: seed does not derive the public key of keypairRef %q", ref.Path, keyID)
	}
	return priv, nil
}
