// TypeScript/JS leg of the ATX v1.1 JCS byte-agreement gate.
//
// For each vector under ../vectors, independently recompute the canonical bytes
// from the vector's `tbs` object using erdtman/canonicalize (the RFC 8785
// reference implementation, the same library the Secretless broker ATX verifier
// will use), then assert they reproduce the pinned expected.canonicalHex
// byte-for-byte. Agreement on the canonical bytes is the property this leg
// proves; signature verification is covered by the Go leg.
//
// Exit 0 iff every vector reproduces its pinned hex. Run via ../run-agreement.sh.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Buffer } from "node:buffer";
import canonicalize from "canonicalize";

const here = dirname(fileURLToPath(import.meta.url));
const vdir = join(here, "..", "vectors");

const files = readdirSync(vdir)
  .filter((f) => f.endsWith(".json"))
  .sort();

if (files.length === 0) {
  process.stderr.write(`[ts] error: no vector files in ${vdir}\n`);
  process.exit(2);
}

const hexByName = {};
let npass = 0;
let nfail = 0;

for (const f of files) {
  const vec = JSON.parse(readFileSync(join(vdir, f), "utf8"));
  const name = vec.name;
  const want = vec.expected.canonicalHex;
  // canonicalize() returns the RFC 8785 canonical UTF-8 string; encode to bytes
  // then hex so the comparison is over exact bytes, not JS string identity.
  const canonicalStr = canonicalize(vec.tbs);
  const got = Buffer.from(canonicalStr, "utf8").toString("hex");
  hexByName[name] = got;
  if (got === want) {
    console.log(`[ts]   PASS  ${name.padEnd(34)}  ${got.length / 2} bytes`);
    npass++;
  } else {
    console.log(`[ts]   FAIL  ${name.padEnd(34)}  canonical hex mismatch`);
    console.log(`       want: ${want}`);
    console.log(`       got:  ${got}`);
    nfail++;
  }
}

const a = hexByName["key-order-scramble"];
const b = hexByName["baseline"];
if (a !== undefined && b !== undefined) {
  if (a === b) {
    console.log(`[ts]   PASS  ${"invariant:scramble==baseline".padEnd(34)}  identical canonical bytes`);
  } else {
    console.log(`[ts]   FAIL  ${"invariant:scramble==baseline".padEnd(34)}  scramble differs from baseline`);
    nfail++;
  }
}

console.log(`\n[ts]     ${npass} pass, ${nfail} fail (${files.length} vectors)`);
process.exit(nfail === 0 ? 0 : 1);
