// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// urlTestFixture stands in for one conformance fixture: the URL adapter only
// reads its Name and Credential.
var urlTestFixture = Fixture{
	Name:       "baseline-valid.json",
	Path:       "fixtures/baseline-valid.json",
	Credential: []byte("{\n    \"id\": \"00000000-0000-0000-0000-000000000001\",\n    \"atcVersion\": \"1.0\",\n    \"trustScore\": 87.5\n  }"),
}

// seen is what a test server observed, guarded for handlers that run
// concurrently with the test.
type seen struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
}

func (s *seen) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r)
	s.bodies = append(s.bodies, body)
}

func (s *seen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// serve starts a test server on 127.0.0.1 and stops it when the test ends.
func serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	if !strings.HasPrefix(s.URL, "http://127.0.0.1:") {
		t.Fatalf("test server is not on 127.0.0.1: %s", s.URL)
	}
	return s
}

// answering returns a handler that records each request and writes status
// and body.
func answering(rec *seen, status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func verifyAt(url string, timeout time.Duration) Result {
	return NewURLAdapter(url, timeout).Verify(context.Background(), urlTestFixture)
}

// TestURLAdapterContractTable holds the adapter to each row of the URL
// contract: 2xx is ACCEPT, 4xx is REJECT, 5xx is COULD_NOT_READ, and a JSON
// "verdict" or "valid" wins over the status, with "reason" recorded.
func TestURLAdapterContractTable(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		want       Verdict
		wantReason string
		wantRaw    string
	}{
		{"200 plain text is ACCEPT", 200, "ok", Accept, "", "ok"},
		{"201 empty body is ACCEPT", 201, "", Accept, "", "HTTP 201 with an empty body"},
		{"204 no body is ACCEPT", 204, "", Accept, "", "HTTP 204 with an empty body"},
		{"299 is ACCEPT", 299, "fine", Accept, "", "fine"},
		{"400 plain text is REJECT", 400, "bad credential", Reject, "", "bad credential"},
		{"422 empty body is REJECT", 422, "", Reject, "", "HTTP 422 with an empty body"},
		{"499 is REJECT", 499, "no", Reject, "", "no"},
		{"500 is COULD_NOT_READ", 500, "internal error", Unreadable, "", "internal error"},
		{"503 empty body is COULD_NOT_READ", 503, "", Unreadable, "", "HTTP 503 with an empty body"},
		{"JSON verdict REJECT wins over 200", 200, `{"verdict":"REJECT"}`, Reject, "", `{"verdict":"REJECT"}`},
		{"JSON verdict ACCEPT wins over 400", 400, `{"verdict":"ACCEPT"}`, Accept, "", `{"verdict":"ACCEPT"}`},
		{"JSON verdict ACCEPT wins over 500", 500, `{"verdict":"ACCEPT"}`, Accept, "", `{"verdict":"ACCEPT"}`},
		{"JSON verdict ERROR wins over 200", 200, `{"verdict":"ERROR"}`, Unreadable, "", `{"verdict":"ERROR"}`},
		{"JSON verdict in lower case", 200, `{"verdict":"reject"}`, Reject, "", `{"verdict":"reject"}`},
		{"JSON valid true wins over 422", 422, `{"valid":true}`, Accept, "", `{"valid":true}`},
		{"JSON valid false wins over 200", 200, `{"valid":false}`, Reject, "", `{"valid":false}`},
		{"JSON reason is recorded", 422, `{"verdict":"REJECT","reason":"signature does not verify"}`, Reject, "signature does not verify", `{"verdict":"REJECT","reason":"signature does not verify"}`},
		{"JSON reason with valid", 200, `{"valid":false,"reason":"expired"}`, Reject, "expired", `{"valid":false,"reason":"expired"}`},
		{"JSON without verdict or valid keeps the status", 200, `{"status":"ok"}`, Accept, "", `{"status":"ok"}`},
		{"JSON with an unknown verdict keeps the status", 400, `{"verdict":"MAYBE"}`, Reject, "", `{"verdict":"MAYBE"}`},
		{"JSON with an unknown verdict leaves valid false to decide over 200", 200, `{"verdict":"INVALID","valid":false}`, Reject, "", `{"verdict":"INVALID","valid":false}`},
		{"JSON with an unknown verdict and a reason leaves valid false to decide over 200", 200, `{"verdict":"INVALID","valid":false,"reason":"expired"}`, Reject, "expired", `{"verdict":"INVALID","valid":false,"reason":"expired"}`},
		{"JSON with an unknown verdict leaves valid true to decide over 400", 400, `{"verdict":"rejected","valid":true}`, Accept, "", `{"verdict":"rejected","valid":true}`},
		{"JSON with an unknown verdict and no valid keeps 200", 200, `{"verdict":"MAYBE"}`, Accept, "", `{"verdict":"MAYBE"}`},
		{"JSON that is not an object keeps the status", 500, `["ACCEPT"]`, Unreadable, "", `["ACCEPT"]`},
		{"JSON valid false with an object reason wins over 200", 200, `{"valid":false,"reason":{"code":"expired"}}`, Reject, "", `{"valid":false,"reason":{"code":"expired"}}`},
		{"JSON verdict REJECT with a number reason wins over 200", 200, `{"verdict":"REJECT","reason":42}`, Reject, "", `{"verdict":"REJECT","reason":42}`},
		{"JSON verdict REJECT with a list reason wins over 200", 200, `{"verdict":"REJECT","reason":["expired"]}`, Reject, "", `{"verdict":"REJECT","reason":["expired"]}`},
		{"JSON verdict ACCEPT with an object reason wins over 422", 422, `{"verdict":"ACCEPT","reason":{"e":1}}`, Accept, "", `{"verdict":"ACCEPT","reason":{"e":1}}`},
		{"JSON verdict ERROR with an object reason wins over 200", 200, `{"verdict":"ERROR","reason":{"e":1}}`, Unreadable, "", `{"verdict":"ERROR","reason":{"e":1}}`},
		{"JSON null reason is no reason", 200, `{"verdict":"REJECT","reason":null}`, Reject, "", `{"verdict":"REJECT","reason":null}`},
		{"JSON verdict of another type leaves valid to decide", 200, `{"verdict":42,"valid":false}`, Reject, "", `{"verdict":42,"valid":false}`},
		{"JSON verdict of another type keeps the status", 200, `{"verdict":{"x":1}}`, Accept, "", `{"verdict":{"x":1}}`},
		{"JSON valid text is not false: 200 keeps ACCEPT", 200, `{"valid":"false"}`, Accept, "", `{"valid":"false"}`},
		{"JSON valid text is not false: 200 with \"true\" keeps ACCEPT", 200, `{"valid":"true"}`, Accept, "", `{"valid":"true"}`},
		{"JSON valid text is not true: 422 keeps REJECT", 422, `{"valid":"true"}`, Reject, "", `{"valid":"true"}`},
		{"JSON valid number keeps the status", 500, `{"valid":1}`, Unreadable, "", `{"valid":1}`},
		{"a log line before the JSON keeps the status", 200, "loaded 3 keys\n" + `{"verdict":"REJECT"}`, Accept, "", "loaded 3 keys\n" + `{"verdict":"REJECT"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &seen{}
			s := serve(t, answering(rec, c.status, c.body))
			got := verifyAt(s.URL, 5*time.Second)
			if got.Verdict != c.want || got.Reason != c.wantReason || got.Raw != c.wantRaw {
				t.Errorf("HTTP %d %q: got %+v, want verdict %s reason %q raw %q", c.status, c.body, got, c.want, c.wantReason, c.wantRaw)
			}
			if n := rec.count(); n != 1 {
				t.Errorf("server saw %d requests, want exactly 1 (no retries)", n)
			}
		})
	}
}

// TestURLAdapterSendsTheCredentialOnly checks the request itself: one POST
// to the URL as given, the credential bytes unchanged as the body, JSON
// content type, the fixture named in its header, and no other header that
// could identify the person running the kit.
func TestURLAdapterSendsTheCredentialOnly(t *testing.T) {
	rec := &seen{}
	s := serve(t, answering(rec, 200, `{"verdict":"ACCEPT"}`))
	got := verifyAt(s.URL+"/verify?suite=atx", 5*time.Second)
	if got.Verdict != Accept {
		t.Fatalf("got %+v, want ACCEPT", got)
	}
	if rec.count() != 1 {
		t.Fatalf("server saw %d requests, want 1", rec.count())
	}
	r, body := rec.requests[0], rec.bodies[0]
	if r.Method != http.MethodPost {
		t.Errorf("method %s, want POST", r.Method)
	}
	if r.URL.Path != "/verify" || r.URL.RawQuery != "suite=atx" {
		t.Errorf("request went to %s, want /verify?suite=atx", r.URL.RequestURI())
	}
	if string(body) != string(urlTestFixture.Credential) {
		t.Errorf("body %q, want the credential bytes unchanged %q", body, urlTestFixture.Credential)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, want application/json", ct)
	}
	if name := r.Header.Get(FixtureHeader); name != urlTestFixture.Name {
		t.Errorf("%s header %q, want %q", FixtureHeader, name, urlTestFixture.Name)
	}
	if ua := r.Header.Get("User-Agent"); ua != "atx-verify" {
		t.Errorf("User-Agent %q, want atx-verify", ua)
	}
	allowed := map[string]bool{"Content-Type": true, "Content-Length": true, "User-Agent": true, "Atx-Fixture": true, "Connection": true}
	var names []string
	for name := range r.Header {
		names = append(names, name)
		if !allowed[name] {
			t.Errorf("unexpected request header %s: %q", name, r.Header.Get(name))
		}
	}
	sort.Strings(names)
	t.Logf("request headers: %s", strings.Join(names, ", "))
}

// TestURLAdapterOmitsAFixtureNameAHeaderCannotCarry leaves the header out
// rather than failing the request or sending a mangled name.
func TestURLAdapterOmitsAFixtureNameAHeaderCannotCarry(t *testing.T) {
	for _, name := range []string{"", "line\nbreak.json", "caf\u00e9.json"} {
		rec := &seen{}
		s := serve(t, answering(rec, 200, "ok"))
		f := urlTestFixture
		f.Name = name
		if got := NewURLAdapter(s.URL, 5*time.Second).Verify(context.Background(), f); got.Verdict != Accept {
			t.Errorf("name %q: got %+v, want ACCEPT", name, got)
		}
		if rec.count() != 1 {
			t.Fatalf("name %q: server saw %d requests, want 1", name, rec.count())
		}
		if v, ok := rec.requests[0].Header[FixtureHeader]; ok {
			t.Errorf("name %q: %s header sent as %q, want it left out", name, FixtureHeader, v)
		}
	}
}

// TestURLAdapterRawCaptureIs200Characters keeps the first 200 characters of
// a long answer, counted as characters rather than bytes.
func TestURLAdapterRawCaptureIs200Characters(t *testing.T) {
	for _, unit := range []string{"x", "\u00e9", "\u4e16"} {
		long := strings.Repeat(unit, 500)
		s := serve(t, answering(&seen{}, 422, long))
		got := verifyAt(s.URL, 5*time.Second)
		if got.Verdict != Reject {
			t.Errorf("%q: verdict %s, want REJECT", unit, got.Verdict)
		}
		if n := utf8.RuneCountInString(got.Raw); n != 200 || got.Raw != strings.Repeat(unit, 200) {
			t.Errorf("%q: raw capture holds %d characters, want the first 200", unit, n)
		}
	}
}

// TestURLAdapterHungServerIsATimeout stops waiting at the timeout, whether
// the server never answers or stops halfway through its body, and never
// takes a 200 status line alone as ACCEPT.
func TestURLAdapterHungServerIsATimeout(t *testing.T) {
	release := make(chan struct{})
	s := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/half" {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"verdict":`)
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release) })

	const timeout = 300 * time.Millisecond
	for _, path := range []string{"/silent", "/half"} {
		start := time.Now()
		got := verifyAt(s.URL+path, timeout)
		elapsed := time.Since(start)
		if got.Verdict != Unreadable {
			t.Errorf("%s: verdict %s, want %s", path, got.Verdict, Unreadable)
		}
		if !strings.Contains(got.Raw, "no answer within 300ms (timeout)") {
			t.Errorf("%s: raw %q does not say it timed out", path, got.Raw)
		}
		if elapsed > 5*time.Second {
			t.Errorf("%s: took %s, want about %s", path, elapsed, timeout)
		}
	}
}

// TestURLAdapterClosedPortIsNoAnswer reports a port nothing listens on as
// COULD_NOT_READ, with what happened in the raw capture.
func TestURLAdapterClosedPortIsNoAnswer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got := verifyAt("http://"+addr+"/", 5*time.Second)
	if got.Verdict != Unreadable || !strings.HasPrefix(got.Raw, "no answer: ") {
		t.Errorf("got %+v, want %s with a raw capture that starts \"no answer: \"", got, Unreadable)
	}
	t.Logf("raw: %s", got.Raw)
}

// TestURLAdapterDroppedConnectionIsNotRetried sends one request when the
// server closes the connection without answering.
func TestURLAdapterDroppedConnectionIsNotRetried(t *testing.T) {
	rec := &seen{}
	s := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	got := verifyAt(s.URL, 5*time.Second)
	if got.Verdict != Unreadable || !strings.HasPrefix(got.Raw, "no answer: ") {
		t.Errorf("got %+v, want %s with \"no answer: \"", got, Unreadable)
	}
	if n := rec.count(); n != 1 {
		t.Errorf("server saw %d requests, want exactly 1 (no retries)", n)
	}
}

// TestURLAdapterRedirects follows a 307 or 308 to the same origin with the
// body intact, and follows nothing else.
func TestURLAdapterRedirects(t *testing.T) {
	t.Run("another host is not followed", func(t *testing.T) {
		other := &seen{}
		b := serve(t, answering(other, 200, `{"verdict":"ACCEPT"}`))
		a := serve(t, http.RedirectHandler(b.URL+"/verify", http.StatusTemporaryRedirect))
		got := verifyAt(a.URL, 5*time.Second)
		if got.Verdict != Unreadable || !strings.Contains(got.Raw, "redirect") {
			t.Errorf("got %+v, want %s naming the redirect", got, Unreadable)
		}
		if n := other.count(); n != 0 {
			t.Errorf("the other host received %d requests, want 0", n)
		}
	})
	t.Run("same origin 307 is followed with the body", func(t *testing.T) {
		rec := &seen{}
		mux := http.NewServeMux()
		mux.Handle("/a", http.RedirectHandler("/b", http.StatusTemporaryRedirect))
		mux.Handle("/b", answering(rec, 422, `{"verdict":"REJECT","reason":"expired"}`))
		s := serve(t, mux)
		got := verifyAt(s.URL+"/a", 5*time.Second)
		if got.Verdict != Reject || got.Reason != "expired" {
			t.Errorf("got %+v, want REJECT with reason expired", got)
		}
		if rec.count() != 1 || string(rec.bodies[0]) != string(urlTestFixture.Credential) || rec.requests[0].Method != http.MethodPost {
			t.Errorf("redirect target did not receive one POST of the credential")
		}
	})
	t.Run("same origin 302 is not followed, it would become a GET", func(t *testing.T) {
		rec := &seen{}
		mux := http.NewServeMux()
		mux.Handle("/a", http.RedirectHandler("/b", http.StatusFound))
		mux.Handle("/b", answering(rec, 200, "ok"))
		s := serve(t, mux)
		got := verifyAt(s.URL+"/a", 5*time.Second)
		if got.Verdict != Unreadable || !strings.Contains(got.Raw, "HTTP 302") {
			t.Errorf("got %+v, want %s naming HTTP 302", got, Unreadable)
		}
		if rec.count() != 0 {
			t.Errorf("redirect target received %d requests, want 0", rec.count())
		}
	})
	t.Run("a redirect loop stops", func(t *testing.T) {
		rec := &seen{}
		s := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec.record(r)
			http.Redirect(w, r, "/again", http.StatusPermanentRedirect)
		}))
		got := verifyAt(s.URL+"/start", 5*time.Second)
		if got.Verdict != Unreadable {
			t.Errorf("got %+v, want %s", got, Unreadable)
		}
		if n := rec.count(); n != maxRedirects+1 {
			t.Errorf("server saw %d requests, want %d", n, maxRedirects+1)
		}
	})
}

// TestURLAdapterRefusesAURLItCannotPost sends nothing for a URL that is not
// an absolute http or https URL, and says why on every fixture.
func TestURLAdapterRefusesAURLItCannotPost(t *testing.T) {
	for _, bad := range []string{"", "localhost:8080", "127.0.0.1:8080/verify", "ftp://127.0.0.1/", "http://", "http//127.0.0.1:8080/", "file:///tmp/x.json"} {
		if CheckURL(bad) == nil {
			t.Errorf("CheckURL(%q) = nil, want an error", bad)
		}
		got := verifyAt(bad, time.Second)
		if got.Verdict != Unreadable || !strings.Contains(got.Raw, "must start with http:// or https://") {
			t.Errorf("%q: got %+v, want %s saying why", bad, got, Unreadable)
		}
	}
	for _, good := range []string{"http://127.0.0.1:8080/", "https://verifier.example/verify", "HTTP://127.0.0.1:1/x?y=z", "http://[::1]:8080/"} {
		if err := CheckURL(good); err != nil {
			t.Errorf("CheckURL(%q) = %v, want nil", good, err)
		}
	}
}

// TestURLAdapterSettings pins the transport choices the contract depends on:
// the default timeout, no proxy, a new connection per request (so the
// transport has no idle connection to retry on) and no compression header.
func TestURLAdapterSettings(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		if a := NewURLAdapter("http://127.0.0.1:1/", timeout).(*urlAdapter); a.timeout != DefaultURLTimeout {
			t.Errorf("timeout %s: adapter waits %s, want %s", timeout, a.timeout, DefaultURLTimeout)
		}
	}
	a := NewURLAdapter("http://127.0.0.1:1/", time.Second).(*urlAdapter)
	tr, ok := a.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", a.client.Transport)
	}
	if tr.Proxy != nil {
		t.Error("transport has a proxy function; the adapter must connect to the URL itself")
	}
	if !tr.DisableKeepAlives || !tr.DisableCompression {
		t.Errorf("DisableKeepAlives %t DisableCompression %t, want both true", tr.DisableKeepAlives, tr.DisableCompression)
	}
}

// TestURLAdapterStopsWhenTheCallerCancels returns at once for a context the
// caller already cancelled.
func TestURLAdapterStopsWhenTheCallerCancels(t *testing.T) {
	rec := &seen{}
	s := serve(t, answering(rec, 200, "ok"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := NewURLAdapter(s.URL, 5*time.Second).Verify(ctx, urlTestFixture)
	if got.Verdict != Unreadable || !strings.HasPrefix(got.Raw, "no answer: ") {
		t.Errorf("got %+v, want %s", got, Unreadable)
	}
}

// TestURLAdapterIsSafeForConcurrentUse runs one adapter from many goroutines.
func TestURLAdapterIsSafeForConcurrentUse(t *testing.T) {
	rec := &seen{}
	s := serve(t, answering(rec, 422, `{"verdict":"REJECT"}`))
	a := NewURLAdapter(s.URL, 5*time.Second)
	var wg sync.WaitGroup
	results := make([]Result, 41)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = a.Verify(context.Background(), urlTestFixture)
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r.Verdict != Reject {
			t.Errorf("request %d: got %+v, want REJECT", i, r)
		}
	}
	if rec.count() != len(results) {
		t.Errorf("server saw %d requests, want %d", rec.count(), len(results))
	}
}
