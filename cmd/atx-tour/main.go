// SPDX-License-Identifier: Apache-2.0

// Command atx-tour is a guided tour of the ATX conformance suite, run from a
// clone of this repository:
//
//	go run ./cmd/atx-tour --setup   once, with the network on
//	go run ./cmd/atx-tour --check   the pre-flight, with the network blocked
//	go run ./cmd/atx-tour           the tour
//
// Each step runs real commands from the clone and shows the lines of their
// output that matter. The tour shows only the steps the last pre-flight
// passed. The logic is in package tour.
package main

import (
	"os"

	"github.com/opena2a-standards/atx-conformance/tour"
)

func main() {
	os.Exit(tour.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
