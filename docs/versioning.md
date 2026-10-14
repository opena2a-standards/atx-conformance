# atx-conformance: versioning and stability

What may change in this repository between commits, and what ships under a
new name. The versions it is pinned to are in
[version-pinning.md](version-pinning.md).

## Versioning and stability

- The conformance fixture file format (`$schema: fixture-v1`) is stable
  across patch revisions of this repository. Adding new fixture fields is
  a minor version bump; renaming or removing fields is a major version
  bump. The format is defined by
  [`schemas/fixture-v1.schema.json`](../schemas/fixture-v1.schema.json), and
  `conformance.json` by
  [`schemas/conformance-profile-v1.schema.json`](../schemas/conformance-profile-v1.schema.json).
  The `$schema` URI a document carries is that file's `$id`, an identifier:
  the host it names does not serve the file, so read the schema from this
  repository at the commit you pin.
- The set of fixtures may grow. New fixtures are additive and do not
  invalidate prior `MANIFEST.sha256` entries; each new fixture appears as
  a new line in the manifest.
- Existing fixtures are immutable in the part that defines them: the
  credential, its signatures, the verifier state and the expected outcome.
  A fixture that needs to change in any of those ships under a new name.
  That is what makes `MANIFEST.sha256` a useful regression check.
  [`scripts/check_fixture_immutability.py`](../scripts/check_fixture_immutability.py)
  compares the `atx`, `verifierState` and `expected` members of every
  fixture name with the merge base of `HEAD` and `origin/main`, and fails
  when one of them changed. The rule was broken once, in e2f9dc4 (#26);
  [`CHANGELOG.md`](../CHANGELOG.md) lists the 22 fixtures that commit changed
  under their existing names.
- A fixture's `description`, its `requirement` and its `spec` citation
  list are documentation, and may be corrected in place. Doing so changes that
  fixture's hash and its manifest line, so a consumer pinning this
  repository at a commit sees no change until they bump deliberately.
  Documentation that is wrong and cannot be fixed without minting a
  duplicate credential under a new name is the worse outcome of the two.
- A citation correction usually touches every fixture at once: moving the
  pinned atx-spec commit re-points every ATX citation, so every
  `MANIFEST.sha256` line changes in that commit while each fixture's
  credential, signatures, verifier state and expected outcome stay as they
  were.
