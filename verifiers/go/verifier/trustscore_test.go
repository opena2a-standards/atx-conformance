package verifier

import (
	"crypto/sha256"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

// TestTrustScoreReadAsWritten pins that the verifier builds the signed
// payload from the trustScore value the credential writes, decided on every
// digit written, as the Python reference verifier's float() reads it.
// strconv.ParseFloat, which encoding/json reads a float64 with, keeps at most
// 800 digits of a literal and places the decimal point by the digits it kept,
// so it read 875 followed by 900 zeros and e-901, whose value is 87.5, as
// 8.75e-102, and the v1.0 and v1.1 baselines, signed over 87.500000, were
// refused for a signature that covers the value the credential writes.
// atx-conformance#308.
func TestTrustScoreReadAsWritten(t *testing.T) {
	zeros := func(n int) string { return strings.Repeat("0", n) }
	v10, err := loadFixture(repoRoot + "/fixtures/baseline-valid.json")
	if err != nil {
		t.Fatal(err)
	}
	v11 := v11Baseline(t)
	baselines := []struct {
		name string
		f    fixture
	}{{"v1.0", v10}, {"v1.1", v11}}

	// 87.5, the value both baselines are signed over, written long.
	for _, literal := range []string{
		`87.5`,
		`875e-1`,
		"875" + zeros(900) + "e-901",
		"8750" + zeros(1000) + "e-1002",
		"0." + zeros(900) + "875e902",
		"87.5" + zeros(1000),
		"87.5" + zeros(1000) + "e0",
		"87.4999999" + zeros(1000) + "1",
	} {
		for _, b := range baselines {
			if got := verify(withMembers(t, b.f, map[string]string{"trustScore": literal})); !got.Accepted {
				t.Errorf("%s baseline, trustScore %.40s (%d bytes): %.300s, want ACCEPT", b.name, literal, len(literal), got)
			}
		}
	}

	// Controls: another value written long is not the value signed.
	for _, literal := range []string{
		"875" + zeros(900) + "e-902",
		"875" + zeros(900) + "e-900",
		"87.49999" + zeros(1000) + "1",
	} {
		for _, b := range baselines {
			if got := verify(withMembers(t, b.f, map[string]string{"trustScore": literal})); got.Accepted || got.RejectCategory != "SIGNATURE_INVALID" {
				t.Errorf("%s baseline, trustScore %.40s (%d bytes): %.300s, want REJECT[SIGNATURE_INVALID]", b.name, literal, len(literal), got)
			}
		}
	}

	// A trustScore whose value is outside the float64 range is not a
	// float64, however strconv.ParseFloat reads it: 1 followed by 1000 zeros
	// and e-650 is 10^350, which ParseFloat reads as 1e+149.
	for _, literal := range []string{
		`1e400`,
		`-1e400`,
		"1" + zeros(1000) + "e-650",
		"-1" + zeros(1000) + "e-650",
		"0." + zeros(200000) + "1e200400",
	} {
		want := "json: cannot unmarshal number " + literal + " into Go struct field atx.trustScore of type float64"
		for _, b := range baselines {
			if got := verify(withMembers(t, b.f, map[string]string{"trustScore": literal})); got.RejectCategory != "PARSE_ERROR" || got.Reason != want {
				t.Errorf("%s baseline, trustScore %.40s (%d bytes): %.300s, want REJECT[PARSE_ERROR: %.120s]", b.name, literal, len(literal), got, want)
			}
		}
	}

	// A trustScore that is not a number keeps encoding/json's reason.
	const notNumber = "json: cannot unmarshal string into Go struct field atx.trustScore of type float64"
	if got := verify(withMembers(t, v10, map[string]string{"trustScore": `"87.5"`})); got.RejectCategory != "PARSE_ERROR" || got.Reason != notNumber {
		t.Errorf(`trustScore "87.5": %s, want REJECT[PARSE_ERROR: %s]`, got, notNumber)
	}
}

// literalDraws is a stream of numbers, each read from two bytes of the
// SHA-256 of seed, a slash and a counter (seed/0, seed/1, and on): the same
// seed draws the same numbers, so TestNearestFloat64 holds nearestFloat64 to
// the same literals on every run.
type literalDraws struct {
	seed    string
	counter int
	block   []byte
}

// below draws a number from 0 through n-1, for n from 1 through 65536.
func (d *literalDraws) below(n int) int {
	if len(d.block) < 2 {
		sum := sha256.Sum256([]byte(d.seed + "/" + strconv.Itoa(d.counter)))
		d.counter++
		d.block = sum[:]
	}
	v := int(d.block[0])<<8 | int(d.block[1])
	d.block = d.block[2:]
	return v % n
}

// TestNearestFloat64 holds nearestFloat64 to strconv.ParseFloat on literals
// of at most 800 bytes, where ParseFloat reads every digit, and to the
// float64 the exact value rounds to (ties to even) on literals longer than
// that, around the halfway points between adjacent float64s.
func TestNearestFloat64(t *testing.T) {
	zeros := func(n int) string { return strings.Repeat("0", n) }
	for _, literal := range []string{
		`0`, `-0`, `0.0`, `-0.0`, `0e400`, `-0e-400`,
		`87.5`, `-87.5`, `100`, `1e-400`, `-1e-400`, `5e-324`, `2.4703282292062328e-324`, `2.4703282292062327e-324`,
		`1.7976931348623157e308`, `1.7976931348623158e308`, `0.1`, `1E+2`, `1e-7`,
		`9007199254740993`, `123456789012345678901234567890`,
	} {
		want, err := strconv.ParseFloat(literal, 64)
		if err != nil {
			t.Fatalf("strconv.ParseFloat(%s): %v", literal, err)
		}
		if got := nearestFloat64(literal); math.Float64bits(got) != math.Float64bits(want) {
			t.Errorf("nearestFloat64(%s) = %g, want %g", literal, got, want)
		}
	}

	// 5000 literals of at most 437 bytes drawn from literalDraws: an optional
	// minus sign, 1 to 30 integer digits, an optional fraction of 1 to 400
	// digits and an optional exponent from -350 through 349. Each one
	// ParseFloat reads without an error, which is all but those above the
	// float64 range, is compared.
	const decimalDigits = "0123456789"
	draws := &literalDraws{seed: "308"}
	compared := 0
	for i := 0; i < 5000; i++ {
		var b strings.Builder
		if draws.below(2) == 0 {
			b.WriteByte('-')
		}
		intDigits := 1 + draws.below(30)
		for j := 0; j < intDigits; j++ {
			d := draws.below(10)
			if j == 0 && intDigits > 1 && d == 0 {
				d = 1
			}
			b.WriteByte(decimalDigits[d])
		}
		if draws.below(2) == 0 {
			b.WriteByte('.')
			for j := 1 + draws.below(400); j > 0; j-- {
				b.WriteByte(decimalDigits[draws.below(10)])
			}
		}
		if draws.below(2) == 0 {
			b.WriteString("e" + strconv.Itoa(draws.below(700)-350))
		}
		literal := b.String()
		want, err := strconv.ParseFloat(literal, 64)
		if err != nil {
			continue
		}
		compared++
		if got := nearestFloat64(literal); math.Float64bits(got) != math.Float64bits(want) {
			t.Errorf("nearestFloat64(literal %d, %.60s, %d bytes) = %g, want %g", i, literal, len(literal), got, want)
		}
	}
	if compared < 4500 {
		t.Errorf("strconv.ParseFloat read %d of the 5000 drawn literals; want at least 4500, so the comparison is not vacuous", compared)
	}

	// halfway is the exact decimal expansion of the point halfway between x
	// and the next float64 above it, less tiny, written with 1100 digits
	// after the point.
	halfway := func(x float64, tiny *big.Rat) string {
		lo := new(big.Rat).SetFloat64(x)
		hi := new(big.Rat).SetFloat64(math.Nextafter(x, math.Inf(1)))
		mid := new(big.Rat).Add(lo, hi)
		mid.Quo(mid, big.NewRat(2, 1))
		return mid.Sub(mid, tiny).FloatString(1100)
	}
	tiny := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Exp(big.NewInt(10), big.NewInt(1095), nil))
	for _, x := range []float64{1, 87.5, 0.1, 1e-300, 5e-324, 1e300, math.Nextafter(87.5, 0)} {
		up := math.Nextafter(x, math.Inf(1))
		even := x
		if math.Float64bits(x)&1 == 1 {
			even = up
		}
		mid := halfway(x, new(big.Rat))
		fraction := len(mid) - strings.IndexByte(mid, '.') - 1
		for _, tc := range []struct {
			literal string
			want    float64
		}{
			{mid, even},
			{mid + zeros(1000), even},
			{mid + zeros(1000) + "1", up},
			{mid + zeros(1000) + "e0", even},
			{strings.TrimLeft(strings.Replace(mid, ".", "", 1), "0") + zeros(500) + "e-" + strconv.Itoa(fraction+500), even},
			{halfway(x, tiny), x},
			{halfway(x, new(big.Rat).Neg(tiny)), up},
		} {
			if got := nearestFloat64(tc.literal); math.Float64bits(got) != math.Float64bits(tc.want) {
				t.Errorf("nearestFloat64(halfway above %g as %.40s..., %d bytes) = %b, want %b", x, tc.literal, len(tc.literal), got, tc.want)
			}
		}
	}
}

// TestNumberOutsideFloat64Range pins numberOutsideFloat64Range, by which
// readTrustScore refuses a trustScore outside the float64 range, at and
// around 2^1024 - 2^970 (float64OverflowDigits) on literals written short and
// written long, and holds it to strconv.ParseFloat, which rounds at the same
// edge, on each literal of at most 800 bytes, where ParseFloat reads every
// digit. atx-conformance#293 and #308.
func TestNumberOutsideFloat64Range(t *testing.T) {
	edge := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1024), new(big.Int).Lsh(big.NewInt(1), 970))
	if float64OverflowDigits != edge.String() || len(float64OverflowDigits) != 309 {
		t.Fatalf("float64OverflowDigits = %.40s (%d digits), want 2^1024 - 2^970, %.40s (%d digits)", float64OverflowDigits, len(float64OverflowDigits), edge, len(edge.String()))
	}
	above := new(big.Int).Add(edge, big.NewInt(1)).String()
	below := new(big.Int).Sub(edge, big.NewInt(1)).String()
	zeros := func(n int) string { return strings.Repeat("0", n) }
	for _, tc := range []struct {
		literal string
		outside bool
	}{
		// Zero, however written.
		{`0`, false},
		{`-0`, false},
		{`0.0`, false},
		{`0e400`, false},
		{`0.000E-400`, false},
		{"0." + zeros(1000) + "e99999999999999999999", false},
		// In the range.
		{`1`, false},
		{`-1`, false},
		{`1.5`, false},
		{`1e3`, false},
		{`1E+3`, false},
		{`1e-400`, false},
		{`1e-99999999999999999999`, false},
		{`1e308`, false},
		{`0.1e309`, false},
		{`10e307`, false},
		{`1.7976931348623158e308`, false},
		{below, false},
		{"-" + below, false},
		{below + ".9", false},
		{"0." + below + "e309", false},
		{"1" + zeros(1000) + "e-692", false},
		{"1" + zeros(1000) + "e-700", false},
		{below + zeros(1000) + "e-1000", false},
		{"0." + zeros(30000) + "1e30308", false},
		{"0." + zeros(200000) + "1e200308", false},
		// At the edge, which rounds to infinity, and above it.
		{edge.String(), true},
		{"-" + edge.String(), true},
		{edge.String() + ".0", true},
		{edge.String() + ".5", true},
		{above, true},
		{"0." + edge.String() + "e309", true},
		{"0.000" + edge.String() + "E+312", true},
		{edge.String() + "e0", true},
		{`1.7976931348623159e308`, true},
		{`1e309`, true},
		{`0.1e310`, true},
		{`10e308`, true},
		{`1e400`, true},
		{`-1e400`, true},
		{`1E400`, true},
		{`1e+400`, true},
		{`1e99999999999999999999`, true},
		{"1" + zeros(400), true},
		{edge.String() + zeros(1000) + "e-1000", true},
		{"1" + zeros(1000) + "e-691", true},
		{"1" + zeros(1000) + "e-650", true},
		{"-1" + zeros(1000) + "e-650", true},
		{"1" + zeros(1000) + "E-650", true},
		{"1" + zeros(900) + "1e-560", true},
		{"1" + zeros(850) + "e-500", true},
		{"1" + zeros(5000) + "e-4600", true},
		{"0." + zeros(200000) + "1e200400", true},
		{"1" + zeros(1000) + ".5e-650", true},
	} {
		if got := numberOutsideFloat64Range(tc.literal); got != tc.outside {
			t.Errorf("numberOutsideFloat64Range(%.40s, %d bytes) = %v, want %v", tc.literal, len(tc.literal), got, tc.outside)
		}
		if len(tc.literal) > 800 {
			continue
		}
		_, err := strconv.ParseFloat(tc.literal, 64)
		if refused := errors.Is(err, strconv.ErrRange); refused != tc.outside {
			t.Errorf("strconv.ParseFloat(%.40s, %d bytes): %.80v; want ErrRange: %v", tc.literal, len(tc.literal), err, tc.outside)
		}
	}
}
