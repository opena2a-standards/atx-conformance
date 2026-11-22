package main

// This file reads a fixture and computes the bytes its native signatures
// cover. The types ATCSignature, ATCBehavioralProfile, ATCScanSummary, ATX,
// tbsScanSummaryV11, tbsBehavioralProfileV11 and tbsV11, and the functions
// canonicalPayload, canonicalPayloadV11 and projectDeclaredPurposeV11, are
// copied from scripts/generate-fixtures/main.go, the program that signed
// every fixture. That program is a separate module's package main, so it
// cannot be imported. The code is unchanged except that canonicalPayloadV11
// returns its errors instead of panicking, and that the IssuedAt and
// ExpiresAt fields of ATX are of the timestamp type below rather than
// time.Time; the comments are shortened.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/big"
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
	IssuedAt             timestamp             `json:"issuedAt"`
	ExpiresAt            timestamp             `json:"expiresAt"`
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
	// profile holds the atx object's behavioralProfile member as written,
	// and is empty when the object has none.
	profile json.RawMessage
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
// A number is outside the double range by its digits as written
// (numberOutsideFloat64Range), before the RFC 8785 library reads it: that
// library reads a number with strconv.ParseFloat, which built with go1.22.0
// or go1.26.3 reads 1 followed by 1000 zeros and e-650, whose value is
// 10^350, as 1e+149, and built with go1.27.0 refuses it. issuedAt and
// expiresAt are decoded as timestamps (timestamp), so one written with a
// JSON escape, or with a time zone offset hour above 24 or minute above 60,
// is refused whatever the Go release.
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
	members, err := decodeObject(atxRaw)
	if err != nil {
		return nil, fmt.Errorf("%s: atx: %w", path, err)
	}
	if where, literal := numberOutsideDoubleRange(members); where != "" {
		return nil, fmt.Errorf("%s: atx cannot be canonicalized (RFC 8785): %s holds the number %s, which is outside the IEEE 754 double range", path, where, literal)
	}
	if _, err := jcs.Transform(atxRaw); err != nil {
		return nil, fmt.Errorf("%s: atx cannot be canonicalized (RFC 8785): %w", path, err)
	}
	if err := checkMemberCase(members); err != nil {
		return nil, fmt.Errorf("%s: atx: %w", path, err)
	}
	f := &fixture{members: members, root: filepath.Join(filepath.Dir(clean), "..")}
	if err := json.Unmarshal(atxRaw, &f.native); err != nil {
		return nil, fmt.Errorf("%s: atx: %w", path, err)
	}
	var written map[string]json.RawMessage
	if err := json.Unmarshal(atxRaw, &written); err != nil {
		return nil, fmt.Errorf("%s: atx: %w", path, err)
	}
	f.profile = written["behavioralProfile"]
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

// behavioralProfileForm describes the one form of a present
// behavioralProfile that the v1.1 TBS has a value for, in the words of the
// reference verifier's reason for a credential that holds any other.
const behavioralProfileForm = "behavioralProfile, which is not an object of exactly checksum (a string), generatedAt (a timestamp) and observationDays (an integer)"

// profileOutsideForm reports whether profile, the behavioralProfile of a
// "1.1" credential as written, is present, is not null, and is not an
// object that holds checksum as a JSON string, generatedAt as a timestamp
// and observationDays as a JSON integer. The v1.1 TBS has no value for such
// a profile. The typed decode of readFixture reads a member that is null or
// absent as its zero value (an empty checksum, the generatedAt
// 0001-01-01T00:00:00Z, the observationDays 0), so the native bytes hold a
// member the credential does not write, and a native signature made over
// that zero value verifies. The rule is that of projectBehavioralProfileV11
// in verifiers/go/verifier/verify.go, by which the reference verifier
// rejects the credential before it reads a signature. It is applied to the
// members as written, so that its answer does not depend on which
// timestamps the decoder of the Go release reads (timestampAsWritten). One
// clause of that rule is left to uncoveredMember:
// a member outside the three, which it refuses by name once the native
// signatures have verified. A name in another letter case is refused by
// checkMemberCase before this is called. Only a "1.1" credential is
// checked: a "1.0" signature covers no part of behavioralProfile.
func profileOutsideForm(a *ATX, profile json.RawMessage) bool {
	if a.ATCVersion != atcVersionV11 || len(profile) == 0 || string(profile) == "null" {
		return false // the TBS holds null for a profile that is absent or null
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(profile, &members); err != nil {
		return true
	}
	// A null member leaves its pointer nil, and an absent one has no text
	// to decode.
	var checksum *string
	if err := json.Unmarshal(members["checksum"], &checksum); err != nil || checksum == nil {
		return true
	}
	var observationDays *int
	if err := json.Unmarshal(members["observationDays"], &observationDays); err != nil || observationDays == nil {
		return true
	}
	return !timestampAsWritten(members["generatedAt"])
}

// timestampAsWritten reports whether raw, the value of a member as written,
// is a JSON string holding a timestamp as the timestamp type of
// verifiers/go/verifier/verify.go reads one: time.Time's own decoder parses
// the text between the quotes, so a timestamp written with a JSON escape is
// not one, and a time zone offset with an hour above 24 or a minute above 60
// is refused. What encoding/json's decode of a time.Time field reads
// depends on the Go release: built with go1.22.0 it reads an offset of
// +25:00, built with go1.27.0 a timestamp written with an escape, and built
// with go1.26.3 neither. Reading the member as written gives one answer
// under all three.
func timestampAsWritten(raw json.RawMessage) bool {
	if len(raw) == 0 || raw[0] != '"' {
		return false // absent, null, or not a string
	}
	var t time.Time
	if err := t.UnmarshalJSON(raw); err != nil {
		return false
	}
	return !offsetOutOfRange(string(raw[1 : len(raw)-1]))
}

// offsetOutOfRange reports whether s, a timestamp that time.Time's decoder
// has read, ends in a time zone offset whose hour is above 24 or whose
// minute is above 60. It reads the offset as checkOffset does
// (endingOffsetField): the last six bytes, a sign, two digits of hour, a
// colon and two digits of minute.
func offsetOutOfRange(s string) bool {
	return endingOffsetField(s) != ""
}

// timestamp is a time.Time decoded by time.Time's own UnmarshalJSON, which
// parses the bytes between the quotes, so a timestamp written with a JSON
// escape fails to decode, and refused as well when its time zone offset has
// an hour above 24 or a minute above 60 (checkOffset). That is how the
// timestamp type of verifiers/go/verifier/verify.go decodes the issuedAt and
// expiresAt of a credential. What encoding/json reads into a plain time.Time
// field depends on the Go release, as timestampAsWritten says: an issuedAt
// or expiresAt decoded into one was read with an offset of +25:00 built with
// go1.22.0 and written with an escape built with go1.27.0, and refused
// built with go1.26.3. Decoded as this type, each is read as the reference
// verifier reads it, and the error that refuses one is the verifier's
// reason, whatever the Go release. The type, its UnmarshalJSON, and
// offsetFirst, checkOffset, endingOffsetField, offsetField and
// offsetRangeError are copied from that file; the code is unchanged.
type timestamp struct{ time.Time }

func (t *timestamp) UnmarshalJSON(b []byte) error {
	if err := t.Time.UnmarshalJSON(b); err != nil {
		return offsetFirst(err)
	}
	if s := string(b); s != "null" {
		return checkOffset(s[1 : len(s)-1])
	}
	return nil
}

// offsetFirst returns the error Go 1.23 and later return for a timestamp in
// place of err, the error time.Time's decoder returned for it, when err
// names something other than the time zone offset and offsetField refuses
// the offset. Go 1.23 and later check the offset's range as soon as they
// have read its hour and minute, so they return the offset's error before
// that of the day, of any text after the offset, or of the offset's sign or
// a minute that is not two digits. Go 1.22 does not check the range, and
// returns the day's error for 2026-02-30T00:00:00+25:00, the extra text's
// for 2099-12-31T23:59:59+25:00x and one that cannot parse the offset for
// 2026-02-30T00:00:00+25:0a.
func offsetFirst(err error) error {
	var pe *time.ParseError
	if !errors.As(err, &pe) {
		return err
	}
	field := ""
	switch {
	case pe.Message == ": day out of range":
		field = endingOffsetField(pe.Value)
	case strings.HasPrefix(pe.Message, ": extra text: ") && strings.HasSuffix(pe.Value, pe.ValueElem):
		field = endingOffsetField(strings.TrimSuffix(pe.Value, pe.ValueElem))
	case pe.Message == "" && pe.LayoutElem == "Z07:00":
		field = offsetField(pe.ValueElem)
	}
	if offsetErr := offsetRangeError(pe.Value, field); offsetErr != nil {
		return offsetErr
	}
	return err
}

// checkOffset refuses a timestamp that time.Time's decoder has read when its
// time zone offset has an hour above 24 or a minute above 60, with the error
// Go 1.23 and later return for it. Go 1.22 decodes such an offset (+25:00,
// +23:61) and Go 1.23 and later refuse it. An offset of +24:00 or +23:60
// decodes under every release.
func checkOffset(s string) error {
	return offsetRangeError(s, endingOffsetField(s))
}

// endingOffsetField is offsetField for the offset s ends in, or "" when s
// ends in Z.
func endingOffsetField(s string) string {
	if len(s) < len("+00:00") || s[len(s)-1] == 'Z' {
		return ""
	}
	return offsetField(s[len(s)-len("+00:00"):])
}

// offsetField returns "hour" or "minute", the field Go 1.23 and later name
// when they refuse the time zone offset v starts with, or "". They read the
// offset as six bytes, a sign, two digits of hour, a colon and two digits of
// minute; refuse it for its hour when that is above 24 and for its minute
// when that is above 60, the minute's error winning; read no minute when the
// hour is not two digits; and refuse it for its range whatever its sign is.
func offsetField(v string) string {
	if len(v) < len("+00:00") || v[3] != ':' {
		return ""
	}
	twoDigits := func(s string) (int, bool) {
		if s[0] < '0' || '9' < s[0] || s[1] < '0' || '9' < s[1] {
			return 0, false
		}
		return int(s[0]-'0')*10 + int(s[1]-'0'), true
	}
	hr, ok := twoDigits(v[1:3])
	mm := 0
	if ok {
		mm, _ = twoDigits(v[4:6])
	}
	field := ""
	if hr > 24 {
		field = "hour"
	}
	if mm > 60 {
		field = "minute"
	}
	return field
}

// offsetRangeError is the error Go 1.23 and later return for timestamp s
// when they refuse its time zone offset for field, or nil when field is "".
func offsetRangeError(s, field string) error {
	if field == "" {
		return nil
	}
	return &time.ParseError{Layout: time.RFC3339, Value: s, Message: ": time zone offset " + field + " out of range"}
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
// object holding a number outside the IEEE 754 double range by its digits
// as written (numberOutsideDoubleRange), and its typed decode one holding an
// integer member outside the int range, so the rule reads neither.
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

// numberOutsideDoubleRange names the first number of the atx object, its
// members decoded with numbers as written (decodeObject), whose magnitude is
// outside the IEEE 754 double range (numberOutsideFloat64Range): where is
// the atx member that holds it, and literal the number as written. It reads
// the members in the order of their names, as firstNumber reads each value.
func numberOutsideDoubleRange(members map[string]any) (where, literal string) {
	for _, name := range sortedNames(members) {
		if literal, found := firstNumber(members[name], numberOutsideFloat64Range); found {
			return name, literal
		}
	}
	return "", ""
}

// firstNumber returns the first number of v, a value decoded with numbers as
// written, for which match holds: v itself, or for an object the first of
// its members' values in the order of their names, for an array the first
// of its elements in their order.
func firstNumber(v any, match func(literal string) bool) (string, bool) {
	switch v := v.(type) {
	case json.Number:
		if match(string(v)) {
			return string(v), true
		}
	case map[string]any:
		for _, name := range sortedNames(v) {
			if literal, found := firstNumber(v[name], match); found {
				return literal, true
			}
		}
	case []any:
		for _, element := range v {
			if literal, found := firstNumber(element, match); found {
				return literal, true
			}
		}
	}
	return "", false
}

// float64OverflowDigits is 2^1024 - 2^970 in decimal digits: the largest
// float64 plus half a unit in its last place, the least magnitude IEEE 754
// round-to-nearest-even takes to infinity, since the tie rounds to the even
// significand, 2^1024. It has 309 digits.
var float64OverflowDigits = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1024), new(big.Int).Lsh(big.NewInt(1), 970)).String()

// numberOutsideFloat64Range reports whether the JSON number literal s has a
// magnitude of 2^1024 - 2^970 or more, which rounds to infinity as a
// float64 (float64OverflowDigits). It decides on the digits as written,
// whatever their count and whatever the exponent, so its answer does not
// depend on the Go release, where strconv.ParseFloat's does. A literal with
// no nonzero digit is zero. Any other is 0.d1d2d3... × 10^point, with d1 its
// first nonzero digit and point the count of digits before the decimal point
// from d1 on, plus the exponent: it is outside the range when point is above
// 309, and when point is 309 and its digits, those past the last written
// being zero, are those of 2^1024 - 2^970 or above them. This function,
// decimalForm and nearestFloat64 are copied from
// verifiers/go/verifier/verify.go; the code is unchanged.
func numberOutsideFloat64Range(s string) bool {
	_, digits, point := decimalForm(s)
	if digits == "" {
		return false
	}
	switch {
	case point > len(float64OverflowDigits):
		return true
	case point < len(float64OverflowDigits):
		return false
	}
	for i := 0; i < len(float64OverflowDigits); i++ {
		d := byte('0')
		if i < len(digits) {
			d = digits[i]
		}
		if d != float64OverflowDigits[i] {
			return d > float64OverflowDigits[i]
		}
	}
	return true
}

// decimalForm reads the JSON number literal s as negative, whether it opens
// with a minus sign; digits, its digits from the first nonzero one on (none
// for a literal with no nonzero digit); and point, such that the magnitude
// of s is 0.digits × 10^point. An exponent is read up to 400 past the length
// of s, which decides the magnitude of any literal on its own
// (numberOutsideFloat64Range).
func decimalForm(s string) (negative bool, digits string, point int) {
	negative = strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mantissa, exponent := s, ""
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mantissa, exponent = s[:i], s[i+1:]
	}
	point = strings.IndexByte(mantissa, '.')
	if point < 0 {
		point = len(mantissa)
	}
	written := strings.Replace(mantissa, ".", "", 1)
	digits = strings.TrimLeft(written, "0")
	if digits == "" {
		return negative, "", 0
	}
	point -= len(written) - len(digits)
	if exponent != "" {
		negativeExponent := exponent[0] == '-'
		if negativeExponent || exponent[0] == '+' {
			exponent = exponent[1:]
		}
		e, limit := 0, len(s)+400
		for i := 0; i < len(exponent) && e < limit; i++ {
			e = e*10 + int(exponent[i]-'0')
		}
		if negativeExponent {
			e = -e
		}
		point += e
	}
	return negative, digits, point
}

// nearestFloat64 returns the float64 nearest the value of the JSON number
// literal s, ties to even, decided on every digit written. The caller has
// refused a literal outside the float64 range (numberOutsideFloat64Range).
// In go1.26 strconv.ParseFloat keeps at most 800 digits of a literal and
// places the decimal point by the digits it kept, so it reads 875 followed
// by 900 zeros and e-901, whose value is 87.5, as 8.75e-102, where go1.27
// reads 87.5. A magnitude below 10^-400 is zero, keeping the sign. Past 800
// significant digits, the digits after the 800th are read as one nonzero
// digit: a point halfway between two float64s is written with at most 767
// significant digits, so the digits past the 800th decide no rounding but
// whether the value lies above the first 800.
func nearestFloat64(s string) float64 {
	negative, digits, point := decimalForm(s)
	digits = strings.TrimRight(digits, "0")
	var f float64
	if digits != "" && point >= -400 {
		if len(digits) > 800 {
			digits = digits[:800] + "1"
		}
		r, ok := new(big.Rat).SetString(digits + "e" + strconv.Itoa(point-len(digits)))
		if !ok {
			panic("nearestFloat64: " + s + " is not a JSON number")
		}
		f, _ = r.Float64()
	}
	if negative {
		f = math.Copysign(f, -1)
	}
	return f
}

// purposeSurrogateEscape returns the first unpaired UTF-16 surrogate escape
// in the declaredPurpose of a "1.1" credential as the TBS carries it, which
// is as the credential writes it. It returns "" when declaredPurpose holds
// none, when the TBS omits declaredPurpose, and for a "1.0" credential,
// whose signed string holds no part of declaredPurpose.
//
// RFC 8785 §3.2.2.2 requires a canonicalizer to refuse a string holding a
// lone surrogate. jcs.Transform refuses a surrogate escape that another
// backslash-u escape does not follow directly, and readFixture has refused
// an atx object holding one. It reads a surrogate escape followed directly
// by an escape that does not complete the pair as a single U+FFFD, the
// second escape included, where encoding/json, which decodes the
// declaredPurpose the credential carries, reads U+FFFD and then the second
// escape's character. A native signature made over a declaredPurpose that
// holds U+FFFD therefore verifies a credential that writes such a pair of
// escapes in its place, whose declaredPurpose, as the credential carries
// it, holds one more character than the native bytes. The reference
// verifier refuses such a credential before it canonicalizes
// (verifySignatures in verifiers/go/verifier/verify.go), by the rule
// copied below.
func purposeSurrogateEscape(a *ATX) string {
	if a.ATCVersion != atcVersionV11 {
		return ""
	}
	return unpairedSurrogateEscape(projectDeclaredPurposeV11(a.DeclaredPurpose))
}

// unpairedSurrogateEscape returns the first backslash-u escape in the JSON
// text raw that writes one half of a UTF-16 surrogate pair without the
// other: a high surrogate (D800 to DBFF) that the next six bytes do not
// complete with the escape of a low one (DC00 to DFFF), or a low surrogate
// that does not complete a high one. It returns "" when raw has none. raw
// is JSON that encoding/json has decoded, so every backslash in it starts
// an escape inside a string. The function and escapedCodeUnit are copied
// from verifiers/go/verifier/verify.go; the code is unchanged.
func unpairedSurrogateEscape(raw []byte) string {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if raw[i+1] != 'u' || i+6 > len(raw) {
			i++ // the escaped character, a backslash among them
			continue
		}
		unit := escapedCodeUnit(raw[i+2 : i+6])
		if unit < 0xd800 || unit > 0xdfff {
			i += 5
			continue
		}
		if unit < 0xdc00 && i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
			if low := escapedCodeUnit(raw[i+8 : i+12]); 0xdc00 <= low && low <= 0xdfff {
				i += 11
				continue
			}
		}
		return string(raw[i : i+6])
	}
	return ""
}

// escapedCodeUnit is the UTF-16 code unit the four hex digits of a
// backslash-u escape write, or -1 if they are not four hex digits.
func escapedCodeUnit(digits []byte) rune {
	var b [2]byte
	if len(digits) != 4 {
		return -1
	}
	if _, err := hex.Decode(b[:], digits); err != nil {
		return -1
	}
	return rune(b[0])<<8 | rune(b[1])
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
