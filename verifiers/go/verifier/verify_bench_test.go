package verifier

import (
	"path/filepath"
	"strings"
	"testing"
)

// benchmarkFixtures names the fixtures BenchmarkVerify times, each read from
// fixtures/<name>.json: the baseline credential of ATX v1.0 and of v1.1, each
// signed with Ed25519 alone and with Ed25519 plus ML-DSA-65 (the -hybrid
// names). The Python reference verifier's benchmark,
// verifiers/python/bench_verify.py, times the same fixtures under the same
// names, and scripts/test_bench_report.py holds the two lists equal.
var benchmarkFixtures = []string{
	"baseline-valid",
	"baseline-valid-hybrid",
	"v1_1-baseline-valid",
	"v1_1-baseline-valid-hybrid",
}

// benchmarkSink holds the result of each timed call, so the call stays live.
var benchmarkSink result

// acceptedBenchmarkFixture reads fixtures/<name>.json and returns it with the
// result verify reaches on it. It stops tb unless that result accepts the
// credential as the fixture's expected outcome says, so no benchmark figure
// is the time of a run that rejected.
func acceptedBenchmarkFixture(tb testing.TB, name string) (fixture, result) {
	tb.Helper()
	f, err := loadFixture(filepath.Join(repoRoot, "fixtures", name+".json"))
	if err != nil {
		tb.Fatalf("%s: %v", name, err)
	}
	got := verify(f)
	if f.Expected.VerifyResult != "ACCEPT" || !got.Accepted || !matchesExpected(f.Expected, got) {
		tb.Fatalf("%s: expected %s, observed %s; a benchmark fixture must expect and reach ACCEPT",
			name, f.Expected.VerifyResult, got)
	}
	return f, got
}

// BenchmarkVerify times verify, the verification of one credential: the
// strict parse of the fixture's atx member, the checks and every signature it
// declares. Each sub-benchmark, named for its fixture, reads the fixture file
// once before its timer starts, so reading and decoding the file is not
// timed. scripts/bench_report.py runs it with -cpu 1 and prints each figure
// with the commit and the CPU it ran on.
func BenchmarkVerify(b *testing.B) {
	for _, name := range benchmarkFixtures {
		b.Run(name, func(b *testing.B) {
			f, _ := acceptedBenchmarkFixture(b, name)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmarkSink = verify(f)
			}
		})
	}
}

// TestBenchmarkFixturesAreAcceptedWithTheirSignatures holds each fixture
// BenchmarkVerify times to what its name says, since go test without -bench
// runs no benchmark: verify accepts it, as its expected outcome says, with
// every signature it declares valid, an ML-DSA-65 signature among them
// exactly when the name ends in -hybrid, and a second call reaches the same
// result, so each timed call does the same work.
func TestBenchmarkFixturesAreAcceptedWithTheirSignatures(t *testing.T) {
	for _, name := range benchmarkFixtures {
		t.Run(name, func(t *testing.T) {
			f, got := acceptedBenchmarkFixture(t, name)
			hybrid := strings.HasSuffix(name, "-hybrid")
			if got.SigsExpected == 0 || got.SigsValid != got.SigsExpected || !got.Ed25519Valid || got.MLDSA65Valid != hybrid {
				t.Errorf("%s: signatures %d/%d valid (ed25519=%t mldsa65=%t), want all valid with mldsa65=%t",
					name, got.SigsValid, got.SigsExpected, got.Ed25519Valid, got.MLDSA65Valid, hybrid)
			}
			if again := verify(f); again != got {
				t.Errorf("%s: a second call observed %+v, the first %+v", name, again, got)
			}
		})
	}
}
