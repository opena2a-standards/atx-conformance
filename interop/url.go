// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FixtureHeader is the request header that names the fixture file a URL
// adapter request belongs to, for example "ATX-Fixture: baseline-valid.json".
// The request body is the credential alone. A verifier that needs the
// verifier side of a fixture (its clock, trusted issuers and keys) reads it
// from the fixture file this header names: three fixtures carry the same
// credential and differ only in that verifier side, so the body alone cannot
// tell them apart. A verifier that does not need it ignores the header.
const FixtureHeader = "ATX-Fixture"

// DefaultURLTimeout is how long a URL adapter waits for one answer when
// NewURLAdapter is given a timeout of zero or less.
const DefaultURLTimeout = 10 * time.Second

// userAgent names the kit, never the person running it.
const userAgent = "atx-verify"

// maxAnswerBytes bounds how much of one answer the adapter reads. The
// contract needs a verdict, an optional reason and 200 characters of raw text.
const maxAnswerBytes = 1 << 20

// maxRedirects bounds the same-origin redirects a URL adapter follows.
const maxRedirects = 3

type urlAdapter struct {
	url     string
	problem string // set when url is not one the adapter can POST to
	timeout time.Duration
	client  *http.Client
}

// CheckURL reports whether raw is a URL the URL adapter can POST to: an
// absolute http or https URL with a host.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("the verifier URL must start with http:// or https:// and name a host, for example http://127.0.0.1:8080/; got %q", raw)
	}
	return nil
}

// NewURLAdapter returns an Adapter that POSTs each fixture's credential JSON
// (Fixture.Credential, and nothing else) to rawURL with Content-Type
// application/json, once per fixture, and names the fixture file in the
// FixtureHeader request header. A 2xx status is ACCEPT, a 4xx status is
// REJECT, and a 5xx status, no answer or a timeout is COULD_NOT_READ; a JSON
// answer carrying "verdict" or "valid" wins over the status (see Classify).
//
// The adapter connects to rawURL directly, never through a proxy, sends no
// header that identifies the person running it, retries nothing and opens a
// new connection for every request. It follows a redirect only to the same
// scheme, host and port and only when the request stays a POST (307 and 308),
// at most three times; any other redirect is COULD_NOT_READ. A timeout of
// zero or less means DefaultURLTimeout. A URL that CheckURL refuses makes
// every fixture COULD_NOT_READ, and nothing is sent.
func NewURLAdapter(rawURL string, timeout time.Duration) Adapter {
	if timeout <= 0 {
		timeout = DefaultURLTimeout
	}
	a := &urlAdapter{url: rawURL, timeout: timeout}
	if err := CheckURL(rawURL); err != nil {
		a.problem = err.Error()
		return a
	}
	a.client = &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true,
			DisableCompression:  true,
		},
		CheckRedirect: sameOriginPOSTOnly,
	}
	return a
}

// sameOriginPOSTOnly stops at a redirect to another scheme, host or port, at
// one that would turn the POST into a GET (301, 302 and 303), and after
// maxRedirects; the redirect response itself is then the answer.
func sameOriginPOSTOnly(req *http.Request, via []*http.Request) error {
	first := via[0].URL
	if len(via) > maxRedirects || req.Method != http.MethodPost ||
		req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return http.ErrUseLastResponse
	}
	return nil
}

// Verify POSTs one fixture's credential and classifies the answer.
func (a *urlAdapter) Verify(ctx context.Context, f Fixture) Result {
	if a.problem != "" {
		return Result{Verdict: Unreadable, Raw: firstChars(a.problem, 200)}
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(f.Credential))
	if err != nil {
		return a.noAnswer(ctx, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if name := headerValue(f.Name); name != "" {
		req.Header.Set(FixtureHeader, name)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return a.noAnswer(ctx, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		// A status line followed by a body that never finished is no answer.
		return Result{Verdict: Unreadable, Raw: firstChars(fmt.Sprintf("HTTP %d, then %s", resp.StatusCode, a.describe(ctx, err)), 200)}
	}

	fallback := Unreadable
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		fallback = Accept
	case resp.StatusCode >= 400 && resp.StatusCode <= 499:
		fallback = Reject
	}
	r := Classify(fallback, body)
	switch {
	case r.Verdict == Unreadable && resp.StatusCode >= 300 && resp.StatusCode <= 399:
		r.Raw = firstChars(fmt.Sprintf("HTTP %d, a redirect to %q that the kit does not follow", resp.StatusCode, resp.Header.Get("Location")), 200)
	case strings.TrimSpace(r.Raw) == "":
		r.Raw = fmt.Sprintf("HTTP %d with an empty body", resp.StatusCode)
	}
	return r
}

// noAnswer is the result of a request that got no HTTP answer at all.
func (a *urlAdapter) noAnswer(ctx context.Context, err error) Result {
	return Result{Verdict: Unreadable, Raw: firstChars(a.describe(ctx, err), 200)}
}

// describe says what went wrong in words a person reading the report can act on.
func (a *urlAdapter) describe(ctx context.Context, err error) string {
	var timeout interface{ Timeout() bool }
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return fmt.Sprintf("no answer within %s (timeout)", a.timeout)
	}
	// A *url.Error prints the URL with its query, and this text goes into the
	// reports; what went wrong is in its Err.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return "no answer: " + err.Error()
}

// headerValue returns name when it can travel in a header unchanged (printable
// ASCII only), and "" otherwise, in which case the header is not sent.
func headerValue(name string) string {
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return ""
		}
	}
	return strings.TrimSpace(name)
}
