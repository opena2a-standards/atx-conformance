# Verifier wall

`verifiers.json` lists the verifiers whose maintainers ran the interop kit at
a released version and passed: a JSON array of rows, `[]` while there are
none. Its format is [`schemas/wall-v1.schema.json`](../schemas/wall-v1.schema.json).

## A row

| Member | Holds |
|---|---|
| `verifier` | the verifier's name: 1 to 64 letters, digits, spaces and `. _ + -`, opening and closing with a letter or digit |
| `version` | the verifier's version: 1 to 32 letters, digits and `. _ + -`, opening and closing with a letter or digit |
| `date` | the UTC date of the run, `YYYY-MM-DD` |
| `kitVersion` | the released kit version the run used, `vX.Y.Z`, a tag of this repository |
| `fixtureCount` | the fixtures the kit sent: the `fixtures/*.json` files at that tag |
| `agree`, `acceptedMustFail`, `rejectedMustPass`, `couldNotRead` | the run's four outcome counts, which sum to `fixtureCount` |

A row holds no path, link, address or commit. A row is admitted only when
`acceptedMustFail` is 0 and `couldNotRead` is below `fixtureCount`. Rows are
sorted by `verifier`, then `version`, then `kitVersion`, and no two share all
three.

## Adding a row

A row's pull request changes only `wall/verifiers.json`. The link to the run
goes in the pull request body, as one line:

    Run: https://github.com/<owner>/<repo>/actions/runs/<run id>

## Check it

From the repository root:

    python3 -I scripts/check_wall.py

The check uses Python's standard library and git, and opens no network
connection. It prints one line per refusal and exits 1 on any refusal, 0
otherwise. A `kitVersion` tag missing from the clone is a refusal that names
`git fetch --tags`.
