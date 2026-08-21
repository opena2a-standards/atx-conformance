#!/usr/bin/env python3
"""Assert the fixture counts stated in README.md and COSIGNERS.md match.

The README states the expected verifier result in two places: the continuous
verification list ("N pass, 0 fail") and the implementations table ("N / N
PASS"). Both are measurements over fixtures/, so they are enforced here
rather than maintained by hand. They drifted apart once already: the table
still claimed 11 / 11 after the fixture set had grown to 20.

Exit 0 when every stated count matches the fixture set, 1 otherwise.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
FIXTURES = ROOT / "fixtures"
# COSIGNERS.md tells an external cosigner what to observe before they sign.
# It stated 15 while fixtures/ held 20, because only README.md was gated here.
# A number a stranger is asked to verify against is exactly the number that
# must not be maintained by hand.
COSIGNERS = ROOT / "COSIGNERS.md"


def main():
    actual = len(sorted(FIXTURES.glob("*.json")))
    if actual == 0:
        print("no fixtures found; refusing to pass vacuously", file=sys.stderr)
        return 1

    readme = README.read_text(encoding="utf-8")
    failures = []

    if COSIGNERS.exists():
        cosigners = COSIGNERS.read_text(encoding="utf-8")
        cos = re.findall(r"(\d+) pass, (\d+) fail", cosigners)
        if not cos:
            failures.append("no `N pass, 0 fail` claim found in COSIGNERS.md")
        for stated, failed in cos:
            if int(stated) != actual:
                failures.append(
                    f"COSIGNERS.md claims `{stated} pass` but fixtures/ holds {actual}"
                )
            if int(failed) != 0:
                failures.append(f"COSIGNERS.md claims `{failed} fail`, expected 0")
        for n in re.findall(r"\((\d+) fixtures\)", cosigners):
            if int(n) != actual:
                failures.append(
                    f"COSIGNERS.md claims ({n} fixtures) but fixtures/ holds {actual}"
                )

    # "must report `20 pass, 0 fail`" in the continuous-verification list.
    pass_fail = re.findall(r"`(\d+) pass, (\d+) fail`", readme)
    if not pass_fail:
        failures.append("no `N pass, 0 fail` claim found in README")
    for stated, failed in pass_fail:
        if int(stated) != actual:
            failures.append(
                f"README claims `{stated} pass` but fixtures/ holds {actual}"
            )
        if int(failed) != 0:
            failures.append(f"README claims `{failed} fail`, expected 0")

    # "20 / 20 PASS" rows in the implementations table.
    table = re.findall(r"(\d+)\s*/\s*(\d+)\s+PASS", readme)
    if not table:
        failures.append("no `N / N PASS` row found in README")
    for got, total in table:
        if int(total) != actual:
            failures.append(
                f"README implementations table claims {got} / {total} PASS "
                f"but fixtures/ holds {actual}"
            )
        if got != total:
            failures.append(f"README table row {got} / {total} PASS is not a full pass")

    if failures:
        print("README counts do not match fixtures/:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"README and COSIGNERS counts match fixtures/: {actual} fixtures, "
          f"all stated as passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
