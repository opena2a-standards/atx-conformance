// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// The four outcomes of a fixture, as the JSON report writes them.
const (
	outcomeAgree            = "agree"
	outcomeAcceptedMustFail = "acceptedMustFail"
	outcomeRejectedMustPass = "rejectedMustPass"
	outcomeCouldNotRead     = "couldNotRead"
)

// outcomeWords is how the summary and the tables name each outcome.
var outcomeWords = map[string]string{
	outcomeAgree:            "agree",
	outcomeAcceptedMustFail: "accepted what must fail",
	outcomeRejectedMustPass: "rejected what must pass",
	outcomeCouldNotRead:     "couldn't read",
}

// The report file names --report writes.
const (
	reportJSONName = "atx-interop-report.json"
	reportMDName   = "atx-interop-report.md"
)

// noReason is the reason a fixture is grouped under when the verifier gave
// none and printed nothing.
const noReason = "no reason given"

// shareLine ends the summary and the Markdown report.
const shareLine = "These results were not sent anywhere. To share them, open an issue on " +
	"https://github.com/opena2a-standards/atx-conformance titled " +
	"\"<verifier> fails <fixture>.json at <suite commit>\", or email the report to info@opena2a.org."

// compareLimit is the limit every report states before its numbers.
const compareLimit = "The kit compares ACCEPT and REJECT only: it does not compare reject categories or the reasons a verifier gives."

// Report is the JSON report, atx-interop-report.json.
type Report struct {
	Kit            string        `json:"kit"`
	KitVersion     string        `json:"kitVersion"`
	SuiteCommit    string        `json:"suiteCommit"`
	ManifestSHA256 string        `json:"manifestSha256"`
	ManifestCheck  string        `json:"manifestCheck"`
	Label          string        `json:"label"`
	Adapter        string        `json:"adapter"`
	Form           string        `json:"form"`
	TimeoutSeconds float64       `json:"timeoutSeconds"`
	StartedAt      string        `json:"startedAt"`
	FinishedAt     string        `json:"finishedAt"`
	FixtureCount   int           `json:"fixtureCount"`
	Summary        Summary       `json:"summary"`
	TopReasons     []ReasonCount `json:"topReasons"`
	Fixtures       []Row         `json:"fixtures"`
	Limits         string        `json:"limits"`
	InteropNote    string        `json:"interopNote"`
}

// Summary is the four numbers.
type Summary struct {
	Agree            int `json:"agree"`
	AcceptedMustFail int `json:"acceptedMustFail"`
	RejectedMustPass int `json:"rejectedMustPass"`
	CouldNotRead     int `json:"couldNotRead"`
}

// ReasonCount is one of the most common reasons among the fixtures that
// did not agree.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// Row is one fixture of the table.
type Row struct {
	Fixture     string `json:"fixture"`
	Requirement string `json:"requirement"`
	Level       string `json:"level"`
	Expected    string `json:"expected"`
	Verdict     string `json:"verdict"`
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason"`
	Raw         string `json:"raw"`
}

// outcomeOf compares an answer with the answer key. A REJECT agrees with
// any REJECT[CATEGORY].
func outcomeOf(mustAccept bool, v Verdict) string {
	switch {
	case v != Accept && v != Reject:
		return outcomeCouldNotRead
	case (v == Accept) == mustAccept:
		return outcomeAgree
	case v == Accept:
		return outcomeAcceptedMustFail
	default:
		return outcomeRejectedMustPass
	}
}

func (s *Summary) add(outcome string) {
	switch outcome {
	case outcomeAgree:
		s.Agree++
	case outcomeAcceptedMustFail:
		s.AcceptedMustFail++
	case outcomeRejectedMustPass:
		s.RejectedMustPass++
	default:
		s.CouldNotRead++
	}
}

// reasonKey is what a row is grouped under among the most common reasons:
// the verifier's reason, else the first line of the raw answer, else
// noReason.
func reasonKey(r Row) string {
	if s := strings.TrimSpace(r.Reason); s != "" {
		return s
	}
	line, _, _ := strings.Cut(strings.TrimSpace(r.Raw), "\n")
	if line = strings.TrimSpace(line); line != "" {
		return line
	}
	return noReason
}

// topReasons is the three most common reasons among the rows that did not
// agree, most common first, ties in text order.
func topReasons(rows []Row) []ReasonCount {
	counts := map[string]int{}
	for _, r := range rows {
		if r.Outcome != outcomeAgree {
			counts[reasonKey(r)]++
		}
	}
	out := make([]ReasonCount, 0, len(counts))
	for reason, n := range counts {
		out = append(out, ReasonCount{Reason: reason, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// interopNote is the closing sentence, for the interop note.
func interopNote(label string, total int, s Summary, top []ReasonCount) string {
	read := total - s.CouldNotRead
	switch {
	case s.Agree == total:
		return fmt.Sprintf("Verifier %s read %d of %d ATX credentials and agreed with the answer key on every one.", label, read, total)
	case read == 0 && len(top) > 0 && top[0].Count == total:
		return fmt.Sprintf("Verifier %s read 0 of %d ATX credentials; every one came back as couldn't read, with: %s.", label, total, strings.TrimSuffix(top[0].Reason, "."))
	case read == 0 && len(top) > 0:
		return fmt.Sprintf("Verifier %s read 0 of %d ATX credentials; every one came back as couldn't read, most often with: %s.", label, total, strings.TrimSuffix(top[0].Reason, "."))
	}
	note := fmt.Sprintf("Verifier %s read %d of %d ATX credentials and agreed with the answer key on %d; it accepted %d that must fail and rejected %d that must pass",
		label, read, total, s.Agree, s.AcceptedMustFail, s.RejectedMustPass)
	if s.CouldNotRead > 0 {
		note += fmt.Sprintf(", and %d came back as couldn't read", s.CouldNotRead)
	}
	return note + "."
}

// verdictWord is how the tables write a verdict.
func verdictWord(v Verdict) string {
	if v == Unreadable {
		return "couldn't read"
	}
	return string(v)
}

// writeText writes the summary that follows the per-fixture lines: the
// four numbers, the most common reasons, the run details and the sentence
// for the interop note.
func writeText(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "\nSummary for %s (%d fixtures)\n", escapeControls(rep.Label), rep.FixtureCount)
	fmt.Fprintf(w, "  %2d  agree\n", rep.Summary.Agree)
	fmt.Fprintf(w, "  %2d  accepted what must fail\n", rep.Summary.AcceptedMustFail)
	fmt.Fprintf(w, "  %2d  rejected what must pass\n", rep.Summary.RejectedMustPass)
	fmt.Fprintf(w, "  %2d  couldn't read\n", rep.Summary.CouldNotRead)
	fmt.Fprintln(w, "\nMost common reasons")
	if len(rep.TopReasons) == 0 {
		fmt.Fprintln(w, "  none: every fixture agreed")
	}
	for _, r := range rep.TopReasons {
		fmt.Fprintf(w, "  %2d  %s\n", r.Count, escapeControls(r.Reason))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Kit version %s, suite commit %s\n", escapeControls(rep.KitVersion), escapeControls(rep.SuiteCommit))
	fmt.Fprintf(w, "Manifest sha256 %s (%s)\n", rep.ManifestSHA256, rep.ManifestCheck)
	fmt.Fprintf(w, "Run at %s, %s adapter, %s form\n", rep.StartedAt, rep.Adapter, rep.Form)
	fmt.Fprintf(w, "\nFor the interop note: %s\n", escapeControls(rep.InteropNote))
}

// writeReports writes atx-interop-report.json and atx-interop-report.md to
// dir and returns their paths.
func writeReports(dir string, rep *Report) ([]string, error) {
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return nil, err
	}
	jsonPath := filepath.Join(dir, reportJSONName)
	mdPath := filepath.Join(dir, reportMDName)
	if err := os.WriteFile(jsonPath, js.Bytes(), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(mdPath, []byte(markdown(rep)), 0o644); err != nil {
		return nil, err
	}
	return []string{jsonPath, mdPath}, nil
}

// markdown is atx-interop-report.md: the four numbers, the most common
// reasons, the table of every fixture, the run details and the sentence for
// the interop note. Text a verifier or a label supplies is written in code
// spans with its controls escaped, so it is shown and never rendered.
func markdown(rep *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ATX interop report: %s\n\n", code(rep.Label))
	fmt.Fprintf(&b, "%s\n\n", compareLimit)
	b.WriteString("| Outcome | Fixtures |\n|---|---|\n")
	fmt.Fprintf(&b, "| Agree | %d |\n", rep.Summary.Agree)
	fmt.Fprintf(&b, "| Accepted what must fail | %d |\n", rep.Summary.AcceptedMustFail)
	fmt.Fprintf(&b, "| Rejected what must pass | %d |\n", rep.Summary.RejectedMustPass)
	fmt.Fprintf(&b, "| Couldn't read | %d |\n", rep.Summary.CouldNotRead)

	b.WriteString("\n## Most common reasons\n\n")
	if len(rep.TopReasons) == 0 {
		b.WriteString("None: every fixture agreed.\n")
	}
	for i, r := range rep.TopReasons {
		fmt.Fprintf(&b, "%d. %d fixtures: %s\n", i+1, r.Count, code(r.Reason))
	}

	fmt.Fprintf(&b, "\n## All %d fixtures\n\n", rep.FixtureCount)
	b.WriteString("| # | Fixture | Level | Expected | Answered | Outcome | Reason | Raw answer (first 200 characters) |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for i, r := range rep.Fixtures {
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s | %s |\n", i+1,
			code(r.Fixture), cell(r.Level), cell(r.Expected), cell(verdictWord(Verdict(r.Verdict))),
			cell(outcomeWords[r.Outcome]), code(r.Reason), code(r.Raw))
	}

	b.WriteString("\n## Run\n\n| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Label | %s |\n", code(rep.Label))
	fmt.Fprintf(&b, "| Kit version | %s |\n", code(rep.KitVersion))
	fmt.Fprintf(&b, "| Suite commit | %s |\n", code(rep.SuiteCommit))
	fmt.Fprintf(&b, "| Manifest SHA-256 | %s |\n", code(rep.ManifestSHA256))
	fmt.Fprintf(&b, "| Manifest check | %s |\n", cell(rep.ManifestCheck))
	fmt.Fprintf(&b, "| Adapter | %s |\n", cell(rep.Adapter))
	fmt.Fprintf(&b, "| Form | %s |\n", cell(rep.Form))
	fmt.Fprintf(&b, "| Timeout per fixture | %gs |\n", rep.TimeoutSeconds)
	fmt.Fprintf(&b, "| Started | %s |\n", cell(rep.StartedAt))
	fmt.Fprintf(&b, "| Finished | %s |\n", cell(rep.FinishedAt))

	b.WriteString("\n## For the interop note\n\n")
	fmt.Fprintf(&b, "%s\n\n", cell(rep.InteropNote))
	b.WriteString(shareLine + "\n")
	return b.String()
}

// cell is s for a Markdown table cell: controls escaped, | escaped.
func cell(s string) string {
	return strings.ReplaceAll(escapeControls(s), "|", `\|`)
}

// code is s as a Markdown code span for a table cell, or "" for an empty s.
func code(s string) string {
	if s == "" {
		return ""
	}
	s = cell(s)
	longest, run := 0, 0
	for _, c := range s {
		if c == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}

// escapeControls writes each C0 control (U+0000 to U+001F, the line feed
// and the tab among them) and DEL as \xHH and each C1 control (U+0080 to
// U+009F) as \u00HH, and a byte that is not UTF-8 in 0x80 to 0x9F as \xHH,
// as the reference verifier's report does, so text a verifier printed is
// shown on a terminal and never acted on.
func escapeControls(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case 0x80 <= r && r <= 0x9f:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r == utf8.RuneError && size == 1 && 0x80 <= s[i] && s[i] <= 0x9f:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
