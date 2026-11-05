// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"time"
)

// NewURLAdapter stands in for the URL adapter until interop/url.go is in
// this build: every fixture comes back as couldn't read. This file is
// deleted when interop/url.go arrives.
func NewURLAdapter(url string, timeout time.Duration) Adapter {
	return placeholderURLAdapter{}
}

type placeholderURLAdapter struct{}

func (placeholderURLAdapter) Verify(context.Context, Fixture) Result {
	return Result{Verdict: Unreadable, Raw: "the URL adapter is not in this build"}
}
