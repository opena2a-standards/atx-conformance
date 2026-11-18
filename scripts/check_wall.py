#!/usr/bin/env python3
"""Hold a wall file, wall/verifiers.json by default, to the wall's contract.

The wall lists the verifiers whose maintainers ran the interop kit at a
released version and passed: one row per verifier version and kit version.
schemas/wall-v1.schema.json is the row's format. A row names no report,
commit or link: the report stays with the maintainer's run, and the pull
request that adds the row carries the link to that run in its body. So this
check reads the file and git alone. It admits a row only when each of these
holds (the rule's name is the word in parentheses):

  - the file is one JSON array, read as UTF-8 (json);
  - the row is a JSON object that gives no member name twice, in any object
    it holds (repeated-member): JSON readers differ on which of two values
    they keep, so the rules below are not read for such a row;
  - the row has exactly the nine members verifier, version, date, kitVersion,
    fixtureCount, agree, acceptedMustFail, rejectedMustPass and couldNotRead
    (members), each in its form (format): verifier and version are plain
    text of letters, digits and . _ + -, verifier also spaces, opening and
    closing with a letter or digit, at most 64 and 32 characters; date is a
    calendar date written YYYY-MM-DD; kitVersion is a released kit version
    vX.Y.Z; and the five counts are JSON integers, written with no fraction
    or exponent and never true or false, fixtureCount at least 1 and the
    others at least 0;
  - `git rev-parse --verify refs/tags/<kitVersion>^{commit}` succeeds in the
    repository the check reads (tag). A tag that clone lacks is refused with
    the command that fetches it, `git fetch --tags`;
  - fixtureCount is the number of .json blobs directly in fixtures/ at the
    tag's commit (`git ls-tree`, no recursion): the set the kit at that
    version embeds (fixtures.go, `//go:embed fixtures/*.json`) and sends, one
    fixture per file, as interop/suite.go buildSuite counts them
    (fixture-count);
  - agree, acceptedMustFail, rejectedMustPass and couldNotRead sum to
    fixtureCount: the kit gives each fixture one of the four outcomes (sum);
  - acceptedMustFail is 0 and couldNotRead is below fixtureCount, the rule
    by which a run of the kit passes (pass);
  - date is not after today's date in UTC, nor before the UTC date of the
    commit the tag names (date);
  - the rows are sorted by verifier, then version, then kitVersion, each
    compared as a string, code point by code point (order), and no two share
    all three (unique).

The check uses the standard library and git. It imports no network module,
and it runs git only to read the tags, trees and commit dates of one
repository, with every transport refused and no lazy fetch of a missing
object, so it opens no network connection. It prints one line per refusal,
naming the row by its index in the array and its verifier, and the rule,
then a count of the refusals. It exits 1 on any refusal and 0 otherwise.
From the repository root:

    python3 -I scripts/check_wall.py [--file <path>] [--repo <path>]

--file names the wall file to read, by default wall/verifiers.json in the
repository. --repo names the repository whose tags are read, by default the
one this script sits in. A merge gate runs the script as main holds it, with
--file on the pull request's copy of the wall file.
"""

import collections
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WALL = "wall/verifiers.json"

# A row's members, in the order schemas/wall-v1.schema.json lists them.
ROW_MEMBERS = ("verifier", "version", "date", "kitVersion", "fixtureCount", "agree",
               "acceptedMustFail", "rejectedMustPass", "couldNotRead")
# The members the rows are sorted by, and that no two rows share all of.
ROW_KEY = ("verifier", "version", "kitVersion")
# The four outcomes of the kit's Summary (interop/report.go), as a row names
# them: the kit gives each fixture one.
BUCKETS = ("agree", "acceptedMustFail", "rejectedMustPass", "couldNotRead")
COUNTS = ("fixtureCount",) + BUCKETS
# The least value of each count.
LEAST = {name: 1 if name == "fixtureCount" else 0 for name in COUNTS}
# The pattern of each text member, as schemas/wall-v1.schema.json writes it.
# The check matches the whole value, so a line break at its end is refused.
PATTERNS = {
    "verifier": r"^[A-Za-z0-9]([A-Za-z0-9 ._+-]{0,62}[A-Za-z0-9])?$",
    "version": r"^[A-Za-z0-9]([A-Za-z0-9._+-]{0,30}[A-Za-z0-9])?$",
    "date": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    "kitVersion": r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
}
MATCHERS = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
# What each text member must be, in words.
FORMS = {
    "verifier": ("1 to 64 characters of letters, digits, spaces and . _ + -, opening and "
                 "closing with a letter or digit: plain text, so no path, link, address or "
                 "markup"),
    "version": ("1 to 32 characters of letters, digits and . _ + -, opening and closing "
                "with a letter or digit"),
    "date": "a date written YYYY-MM-DD",
    "kitVersion": ("a released kit version vX.Y.Z; a kit tag kit-YYYY-MM-DD or a Go "
                   "pseudo-version is not one"),
}
FETCH = "run `git fetch --tags` and check again"

USAGE = """usage: {name} [--file <path>] [--repo <path>]

Checks each row of a wall file: its members against
schemas/wall-v1.schema.json, its counts against the pass rule (the four
outcomes sum to fixtureCount, acceptedMustFail is 0 and couldNotRead is
below fixtureCount), and its kitVersion against the repository's tags (the
tag is there, fixtureCount is the number of fixtures/*.json files at it,
and the date falls between the date of its commit and today, in UTC).
Prints one line per refusal, and exits 1 on any refusal and 0 otherwise.

  --file <path>  the wall file to read (default: wall/verifiers.json in
                 the repository)
  --repo <path>  the repository whose tags are read (default: the
                 repository this script sits in)"""

Refusal = collections.namedtuple("Refusal", "row rule line")
Checked = collections.namedtuple("Checked", "rows refusals")


def show(value):
    """A string, number, boolean or null as JSON, with every control
    character and every character past ASCII escaped, cut to 80 characters,
    and an array or an object by its kind alone, so a refusal stays one short
    line however deep the value is nested."""
    if isinstance(value, dict):
        return "(an object)"
    if isinstance(value, list):
        return "(an array)"
    text = json.dumps(value, ensure_ascii=True)
    return text if len(text) <= 80 else text[:77] + "..."


def one_line(text):
    """text with every control character and every character past ASCII
    escaped as JSON escapes them, so a refusal stays one line."""
    return "".join(c if " " <= c <= "~" else json.dumps(c)[1:-1] for c in str(text))


def plural(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


class Members(dict):
    """A JSON object's members, and the names the object gives more than
    once."""

    repeated = ()


def members_of(pairs):
    """The object_pairs_hook of read_json: an object's members, with each
    name it gives more than once noted."""
    out = Members()
    repeated = []
    for name, value in pairs:
        if name in out and name not in repeated:
            repeated.append(name)
        out[name] = value
    out.repeated = tuple(repeated)
    return out


def not_a_number(name):
    raise ValueError(f"{name} is not a JSON number")


def read_json(path):
    """The JSON document at path, read as UTF-8. NaN, Infinity and
    -Infinity are refused, and each object notes the names it gives twice."""
    text = pathlib.Path(path).read_bytes().decode("utf-8")
    return json.loads(text, object_pairs_hook=members_of, parse_constant=not_a_number)


def repeated_names(value):
    """The member names that some object in value, value included, gives
    more than once."""
    found, todo = [], [value]
    while todo:
        item = todo.pop()
        if isinstance(item, Members):
            found += [name for name in item.repeated if name not in found]
            todo.extend(item.values())
        elif isinstance(item, list):
            todo.extend(item)
    return found


def form_problem(name, value):
    """What keeps value from being the form of the member name; empty when
    nothing does."""
    if name in COUNTS:
        least = LEAST[name]
        if isinstance(value, bool):
            return f"{name} {show(value)} is a boolean, not an integer of at least {least}"
        if type(value) is not int or value < least:
            return f"{name} {show(value)} is not an integer of at least {least}"
        return ""
    if not isinstance(value, str) or MATCHERS[name].fullmatch(value) is None:
        return f"{name} {show(value)} is not {FORMS[name]}"
    if name == "date":
        try:
            datetime.date.fromisoformat(value)
        except ValueError:
            return f"date {show(value)} is not a calendar date"
    return ""


def members_text(unknown, missing):
    """The unknown and missing members of a row, in words."""
    parts = []
    if unknown:
        parts.append(f"has the unknown member{'s' if len(unknown) > 1 else ''} "
                     + ", ".join(show(name) for name in unknown))
    if missing:
        parts.append(f"lacks the member{'s' if len(missing) > 1 else ''} " + ", ".join(missing))
    return " and ".join(parts)


def git(repo, *args):
    """git run on the repository at repo, with every GIT_ variable of this
    process set aside (one can name another repository or allow a
    transport), every transport refused, no lazy fetch of a missing object,
    and replace refs ignored. Its output is bytes."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", "--no-replace-objects", "-c", "protocol.allow=never", "-C", str(repo), *args],
        capture_output=True, env=env, timeout=60)


def said(done):
    """The first line git wrote to standard error, or its exit status."""
    lines = done.stderr.decode("utf-8", "replace").strip().splitlines()
    return one_line(lines[0]) if lines else f"git exited {done.returncode}"


def count_fixtures(listing):
    """The number of .json blobs a `git ls-tree --full-tree -z <commit>
    fixtures/` listing holds: the files directly in fixtures/, as the kit's
    buildSuite counts them (every entry of fixtures/ that is not a directory
    and whose name ends in .json)."""
    count = 0
    for entry in listing.split(b"\0"):
        info, tab, name = entry.partition(b"\t")
        fields = info.split(b" ")
        leaf = name[len(b"fixtures/"):]
        if (tab and len(fields) == 3 and fields[1] == b"blob" and name.startswith(b"fixtures/")
                and b"/" not in leaf and leaf.endswith(b".json")):
            count += 1
    return count


def utc_date(text):
    """The UTC date of a time git wrote with %cI, ISO 8601 with its offset;
    None when text is not one."""
    try:
        when = datetime.datetime.fromisoformat(text.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return when.astimezone(datetime.timezone.utc).date()


def read_tag(repo, name):
    """What git shows of the tag name, a kitVersion in its form (so never an
    option), in the repository at repo: the commit it names, the number of
    fixtures at that commit and the commit's UTC date, each None when git
    did not show it, and, by rule, why git did not."""
    tag = {"commit": None, "fixtures": None, "day": None,
           "problems": {"tag": [], "fixture-count": [], "date": []}}
    problems = tag["problems"]
    try:
        done = git(repo, "rev-parse", "--verify", "--quiet", f"refs/tags/{name}^{{commit}}")
        if done.returncode == 0 and done.stdout.strip():
            tag["commit"] = done.stdout.decode("ascii", "replace").strip()
        elif done.returncode == 1:
            exists = git(repo, "rev-parse", "--verify", "--quiet", f"refs/tags/{name}")
            if exists.returncode == 1:
                problems["tag"].append(f"kitVersion {name} is not a tag in this clone: {FETCH}")
            elif exists.returncode == 0:
                problems["tag"].append(f"tag {name} names no commit")
            else:
                problems["tag"].append(f"git could not read tag {name}: {said(exists)}")
        else:
            problems["tag"].append(f"git could not read tag {name}: {said(done)}")
        if tag["commit"] is None:
            return tag

        listed = git(repo, "ls-tree", "--full-tree", "-z", tag["commit"], "fixtures/")
        if listed.returncode == 0:
            tag["fixtures"] = count_fixtures(listed.stdout)
        else:
            problems["fixture-count"].append(
                f"git could not list fixtures/ at tag {name}: {said(listed)}")

        dated = git(repo, "log", "-1", "--no-show-signature", "--format=%cI", tag["commit"])
        if dated.returncode != 0:
            problems["date"].append(
                f"git could not read the date of the commit tag {name} names: {said(dated)}")
        else:
            tag["day"] = utc_date(dated.stdout)
            if tag["day"] is None:
                problems["date"].append(
                    f"git gave {show(dated.stdout.decode('utf-8', 'replace').strip())} as the "
                    f"date of the commit tag {name} names, not an ISO 8601 time")
    except (OSError, subprocess.TimeoutExpired) as err:
        problems["tag"].append(f"git could not be run to read tag {name}: {one_line(err)}")
    return tag


def row_refusals(row, tag_of, today):
    """(rule, text) for each rule the row breaks, in the order the module's
    docstring lists the rules, but order and unique, which check() holds.
    row is a JSON object that gives no name twice; tag_of(kitVersion) is
    what git shows of the tag."""
    out = []
    unknown = [name for name in row if name not in ROW_MEMBERS]
    missing = [name for name in ROW_MEMBERS if name not in row]
    if unknown or missing:
        out.append(("members", f"it {members_text(unknown, missing)}; a row has exactly the "
                               f"members {', '.join(ROW_MEMBERS)}"))
    good = {}
    for name in ROW_MEMBERS:
        if name not in row:
            continue
        problem = form_problem(name, row[name])
        if problem:
            out.append(("format", problem))
        else:
            good[name] = row[name]

    tag = tag_of(good["kitVersion"]) if "kitVersion" in good else None
    problems = tag["problems"] if tag else {}
    out += [("tag", text) for text in problems.get("tag", ())]
    if "fixtureCount" in good and tag:
        out += [("fixture-count", text) for text in problems["fixture-count"]]
        if tag["fixtures"] is not None and tag["fixtures"] != good["fixtureCount"]:
            out.append(("fixture-count",
                        f"fixtureCount {good['fixtureCount']} is not {tag['fixtures']}, the number "
                        f"of fixtures/*.json files at tag {good['kitVersion']}: the kit at that "
                        f"version sends each of them once"))

    if all(name in good for name in COUNTS):
        total = sum(good[name] for name in BUCKETS)
        if total != good["fixtureCount"]:
            terms = " + ".join(f"{name} {good[name]}" for name in BUCKETS)
            out.append(("sum", f"{terms} is {total}, not fixtureCount {good['fixtureCount']}: "
                               f"the kit gives each fixture one of the four outcomes"))

    if good.get("acceptedMustFail", 0) != 0:
        out.append(("pass", f"acceptedMustFail is {good['acceptedMustFail']}: the verifier "
                            f"accepted a fixture that must fail, and a run passes only at 0"))
    if ("couldNotRead" in good and "fixtureCount" in good
            and good["couldNotRead"] >= good["fixtureCount"]):
        out.append(("pass", f"couldNotRead {good['couldNotRead']} is not below fixtureCount "
                            f"{good['fixtureCount']}: the kit read none of the verifier's "
                            f"answers, so the run measured nothing"))

    if "date" in good:
        day = datetime.date.fromisoformat(good["date"])
        if day > today:
            out.append(("date", f"date {good['date']} is after {today.isoformat()}, today's "
                                f"date in UTC"))
        if tag:
            out += [("date", text) for text in problems["date"]]
            if tag["day"] is not None and day < tag["day"]:
                out.append(("date", f"date {good['date']} is before {tag['day'].isoformat()}, "
                                    f"the UTC date of the commit tag {good['kitVersion']} names: "
                                    f"a run is not older than the kit it ran"))
    return out


def row_name(index, row):
    """How a refusal line names a row: its index in the array and its
    verifier."""
    if isinstance(row, dict) and "verifier" in row:
        return f"[{index}] (verifier {show(row['verifier'])})"
    return f"[{index}] (no verifier)"


def check(path=None, repo=ROOT, today=None):
    """How many rows the wall file holds (None when it is not one JSON
    array) and the refusals the check makes, the file's first, then by row.
    path is the wall file, by default wall/verifiers.json in repo; repo is
    the repository whose tags are read; today is the current date in UTC
    unless given."""
    repo = pathlib.Path(repo)
    shown = WALL if path is None else one_line(path)
    path = repo / WALL if path is None else pathlib.Path(path)
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    refusals = []

    def refuse(index, rule, text, row=None):
        where = shown if index is None else shown + row_name(index, row)
        refusals.append(Refusal(index, rule, f"refused: {where}: {rule}: {text}"))

    try:
        rows = read_json(path)
    except FileNotFoundError:
        refuse(None, "json", "is not there: the wall file holds a JSON array of rows, [] for none")
        return Checked(None, refusals)
    except OSError as err:
        refuse(None, "json", f"cannot be read: {one_line(err.strerror or err)}")
        return Checked(None, refusals)
    except (ValueError, RecursionError) as err:
        refuse(None, "json", f"cannot be read as JSON: {one_line(err)}")
        return Checked(None, refusals)
    if not isinstance(rows, list):
        refuse(None, "json", "is not a JSON array of rows")
        return Checked(None, refusals)

    tags = {}

    def tag_of(name):
        if name not in tags:
            tags[name] = read_tag(repo, name)
        return tags[name]

    keyed = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            refuse(index, "format", "the row is not a JSON object", row)
            continue
        repeated = repeated_names(row)
        if repeated:
            names = ", ".join(show(name) for name in repeated)
            refuse(index, "repeated-member",
                   f"it gives the member name{'s' if len(repeated) > 1 else ''} {names} more "
                   f"than once; JSON readers differ on which value they keep, so its other rules "
                   f"are not read", row)
            continue
        for rule, text in row_refusals(row, tag_of, today):
            refuse(index, rule, text, row)
        if all(isinstance(row.get(name), str) for name in ROW_KEY):
            keyed.append((index, row, tuple(row[name] for name in ROW_KEY)))

    first_with = {}
    previous = None
    for index, row, key in keyed:
        if key in first_with:
            refuse(index, "unique", f"row [{first_with[key]}] has the same verifier, version and "
                                    f"kitVersion", row)
        else:
            first_with[key] = index
        if previous is not None and previous[1] > key:
            refuse(index, "order", f"it sorts before row [{previous[0]}]: the rows are sorted by "
                                   f"verifier, then version, then kitVersion, each compared as a "
                                   f"string", row)
        previous = (index, key)

    refusals.sort(key=lambda refusal: refusal.row)
    return Checked(len(rows), refusals)


def main():
    args = sys.argv[1:]
    usage = USAGE.format(name=pathlib.Path(sys.argv[0]).name)
    if "-h" in args or "--help" in args:
        print(usage)
        return 0
    given, unknown = {}, []
    rest = iter(args)
    for arg in rest:
        if arg not in ("--file", "--repo"):
            unknown.append(arg)
            continue
        value = next(rest, None)
        if not value:
            print(f"{arg} takes a path", file=sys.stderr)
            print(usage, file=sys.stderr)
            return 2
        if arg in given:
            print(f"{arg} is given twice", file=sys.stderr)
            print(usage, file=sys.stderr)
            return 2
        given[arg] = value
    # An unknown argument must not fall through to the check and exit 0.
    if unknown:
        print(f"unknown argument(s): {one_line(' '.join(unknown))}", file=sys.stderr)
        print(usage, file=sys.stderr)
        return 2

    file = given.get("--file")
    rows, refusals = check(file, given.get("--repo", ROOT))
    shown = WALL if file is None else one_line(file)
    for refusal in refusals:
        print(refusal.line)
    if refusals:
        print(f"{shown}: {plural(len(refusals), 'refusal')}")
        return 1
    print(f"{shown}: {plural(rows, 'row')} admitted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
