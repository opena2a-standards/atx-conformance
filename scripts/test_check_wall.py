#!/usr/bin/env python3
"""check_wall.py admits a row of wall/verifiers.json only when the row has
the wall's form and git confirms what the row says about its kit version.

The wall lists the verifiers whose maintainers ran the interop kit at a
released version and passed by the wall's own rule, acceptedMustFail 0 and
couldNotRead below fixtureCount. That rule is not the kit's exit status,
which is 0 only when every fixture agrees; TheWallsOwnRule holds the texts
that say what passed means on the wall to saying so, and to that exit
status as interop/run.go gives it. A row has nine members: the verifier's
name and version, the UTC date of the run, the released kit version
(kitVersion, vX.Y.Z), the number of fixtures the kit sent and the run's four
outcome counts. It names no report, commit or link: the report stays with
the maintainer's run, and the link to that run goes in the pull request's
body. schemas/wall-v1.schema.json is the row's format. check_wall.py holds a
wall file to that format and, from git alone, to the rules a schema cannot
state: the kitVersion tag is in the clone; fixtureCount is the number of
fixtures/*.json files at that tag, the set the kit at that version embeds;
the outcome counts sum to fixtureCount; acceptedMustFail is 0 and
couldNotRead is below fixtureCount; the date is not after today (UTC) and not
before the UTC date of the tag's commit; the rows are sorted and unique; and
no row names a member twice.

Each case builds a git repository in a temporary directory: one commit holding
three files fixtures/fixture-<n>.json, committed at 2026-11-14T23:30:05-05:00,
which is 2026-11-15 in UTC, with the tag v1.2.0 on it. The case writes rows
there and runs the check on them. The cases' own git commands set aside the
machine's and the user's git configuration and every GIT_ variable of this
process, so a case run from a git hook writes to no other repository: no case
creates a tag or a commit in this one. Every git command, the check's
included, runs with every transport refused, so no case reads the network.
Run from the repository root:

    python3 -I scripts/test_check_wall.py
"""

import ast
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
# python3 -I leaves the script's own directory off sys.path.
sys.path.insert(0, str(SCRIPTS))

import check_wall  # noqa: E402

SCHEMA = ROOT / "schemas" / "wall-v1.schema.json"
REPORT_GO = ROOT / "interop" / "report.go"
RUN_GO = ROOT / "interop" / "run.go"
FIXTURES_GO = ROOT / "fixtures.go"
WALL = ROOT / "wall" / "verifiers.json"
WALL_README = ROOT / "wall" / "README.md"

TAG = "v1.2.0"
FIXTURES = 3
# The date of the tag's commit at its own offset, and that commit's date in
# UTC, one day later.
COMMITTED = "2026-11-14T23:30:05-05:00"
RUN_DATE = "2026-11-15"
ONE_DAY = datetime.timedelta(days=1)
# The modules check_wall.py may import: standard library modules, none of
# them a network module.
STANDARD_MODULES = {"collections", "datetime", "json", "os", "pathlib", "re", "subprocess", "sys"}
# What each text that says what passed means on the wall holds, read by
# plain(): the wall's pass rule, that the rule is not the kit's exit status,
# and what that exit status is.
PASS_RULE = "acceptedMustFail is 0 and couldNotRead is below fixtureCount"
NOT_THE_KITS = "not the kit's exit status"
KIT_EXIT = "the kit exits 0 only when every fixture agrees"
# The end of the kit's run in interop/run.go: exit 1 unless every fixture
# agrees, 0 when every one does.
KIT_EXIT_GO = "\tif rep.Summary.Agree != rep.FixtureCount {\n\t\treturn 1\n\t}\n\treturn 0\n}\n"
# The kit's usage text in interop/run.go on its exit status, read by plain().
KIT_EXIT_USAGE = "Exit status: 0 when every fixture agrees with the answer key, 1 when any does not"


def git(cwd, *args, date=None):
    """What git printed, run in cwd with the machine's and the user's git
    configuration and every GIT_ variable of this process set aside, so a case
    run from a git hook cannot write to the repository the hook runs in. date,
    when given, is the author and committer date of the commit made."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME="wall test", GIT_AUTHOR_EMAIL="wall-test@example.invalid",
               GIT_COMMITTER_NAME="wall test", GIT_COMMITTER_EMAIL="wall-test@example.invalid")
    if date is not None:
        env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    done = subprocess.run(
        ["git", "-c", "protocol.allow=never", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=60)
    if done.returncode:
        raise AssertionError(f"git {' '.join(args)} exited {done.returncode}: {done.stderr}")
    return done.stdout.strip()


def utc_today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def plain(text):
    """text as one line of words in lower case: each run of white space read
    as one space, as a sentence wrapped over several lines reads, and
    Markdown's backticks dropped."""
    return " ".join(text.replace("`", "").split()).lower()


def wall_row(**change):
    """The row a Repo admits, with the changes given."""
    row = {"verifier": "Example Verifier", "version": "0.9.1", "date": RUN_DATE,
           "kitVersion": TAG, "fixtureCount": FIXTURES, "agree": FIXTURES,
           "acceptedMustFail": 0, "rejectedMustPass": 0, "couldNotRead": 0}
    row.update(change)
    return row


class Repo:
    """A git repository in a temporary directory: one commit holding the
    files fixtures/fixture-<n>.json, `fixtures` of them, and the files named
    in `more`, committed at COMMITTED, with the tag TAG on it."""

    def __init__(self, test, fixtures=FIXTURES, more=(), annotated=False):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="test-check-wall-"))
        test.addCleanup(shutil.rmtree, self.base, True)
        self.root = self.base / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q")
        names = [f"fixtures/fixture-{n}.json" for n in range(fixtures)] + list(more)
        for name in names:
            self.write(name, "{}\n")
        git(self.root, "add", "--", *names)
        git(self.root, "commit", "-q", "-m", "suite", date=COMMITTED)
        self.commit = git(self.root, "rev-parse", "HEAD")
        if annotated:
            git(self.root, "tag", "-a", TAG, "-m", TAG)
        else:
            git(self.root, "tag", TAG)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def admit(self, *rows):
        """Writes rows as this repository's wall/verifiers.json."""
        self.write("wall/verifiers.json", json.dumps(list(rows), indent=2) + "\n")

    def refusals(self):
        """(row, rule) for each refusal check_wall.check() makes on this
        repository's wall/verifiers.json; row is None for the file."""
        return [(r.row, r.rule) for r in check_wall.check(repo=self.root).refusals]

    def lines(self):
        """The line check_wall.check() prints for each refusal here."""
        return [r.line for r in check_wall.check(repo=self.root).refusals]

    def run(self, *args, outside=False):
        """check_wall.py run as a process with python3 -I, from a working
        directory outside this repository. The script is a copy in this
        repository's scripts/ directory, which makes this the repository it
        reads by default; with outside, the copy is in a directory of no
        repository, as a merge gate holds the script it read from main."""
        folder = self.base / "gate" if outside else self.root / "scripts"
        folder.mkdir(exist_ok=True)
        script = folder / "check_wall.py"
        shutil.copyfile(SCRIPTS / "check_wall.py", script)
        return subprocess.run([sys.executable, "-I", str(script), *args], cwd=self.base,
                              capture_output=True, text=True, timeout=120)


class Admitted(unittest.TestCase):
    def test_the_empty_file_passes(self):
        repo = Repo(self)
        repo.admit()
        self.assertEqual(repo.refusals(), [])
        done = repo.run()
        self.assertEqual((done.returncode, done.stdout, done.stderr),
                         (0, "wall/verifiers.json: 0 rows admitted\n", ""))

    def test_a_valid_row_passes(self):
        repo = Repo(self)
        repo.admit(wall_row())
        self.assertEqual(repo.refusals(), [])
        done = repo.run()
        self.assertEqual((done.returncode, done.stdout, done.stderr),
                         (0, "wall/verifiers.json: 1 row admitted\n", ""))

    def test_file_on_a_copy_outside_the_repository_passes(self):
        repo = Repo(self)
        # The repository's own file is refused, so a pass reads the copy.
        repo.write("wall/verifiers.json", "{}\n")
        self.assertEqual(repo.run().returncode, 1)
        copy = repo.base / "pull-request" / "verifiers.json"
        copy.parent.mkdir()
        copy.write_text(json.dumps([wall_row()], indent=2) + "\n", encoding="utf-8")
        for label, args, outside in (
                ("the script in the repository", ("--file", str(copy)), False),
                ("the script outside it, --repo naming it",
                 ("--file", str(copy), "--repo", str(repo.root)), True)):
            with self.subTest(label):
                done = repo.run(*args, outside=outside)
                self.assertEqual((done.returncode, done.stdout, done.stderr),
                                 (0, f"{copy}: 1 row admitted\n", ""))


class AlsoAdmitted(unittest.TestCase):
    def test_an_annotated_tag_passes(self):
        repo = Repo(self, annotated=True)
        repo.admit(wall_row())
        self.assertEqual(repo.refusals(), [])

    def test_only_json_files_directly_in_fixtures_are_counted(self):
        repo = Repo(self, more=("fixtures/notes.txt", "fixtures/load-errors/extra.json",
                                "fixtures/folder.json/inner.json", "elsewhere.json"))
        repo.admit(wall_row())
        self.assertEqual(repo.refusals(), [])
        repo.admit(wall_row(fixtureCount=FIXTURES + 2, agree=FIXTURES + 2))
        self.assertEqual(repo.refusals(), [(0, "fixture-count")])

    def test_rejected_must_pass_and_some_could_not_read_pass(self):
        repo = Repo(self)
        repo.admit(wall_row(agree=1, rejectedMustPass=1, couldNotRead=1))
        self.assertEqual(repo.refusals(), [])

    def test_a_date_of_today_passes(self):
        repo = Repo(self)
        for _ in range(2):  # a second try when the UTC date turned during the first
            today = utc_today()
            repo.admit(wall_row(date=today.isoformat()))
            got = repo.refusals()
            if utc_today() == today:
                break
        self.assertEqual(got, [])


class Refused(unittest.TestCase):
    """Each case changes one thing in a row the repository admits, and the
    check refuses that row by the one rule the change breaks."""

    def setUp(self):
        self.repo = Repo(self)

    def refused(self, *rows):
        self.repo.admit(*rows)
        return self.repo.refusals()

    def test_an_unknown_member_is_refused(self):
        self.assertEqual(self.refused(wall_row(note="run on a laptop")), [(0, "members")])

    def test_a_missing_member_is_refused(self):
        row = wall_row()
        del row["date"]
        self.assertEqual(self.refused(row), [(0, "members")])

    def test_a_report_member_is_refused(self):
        row = wall_row(report="wall/reports/example-verifier-0.9.1.json")
        self.assertEqual(self.refused(row), [(0, "members")])
        self.assertIn('unknown member "report"', self.repo.lines()[0])

    def test_a_suite_commit_member_is_refused(self):
        row = wall_row(suiteCommit=self.repo.commit)
        self.assertEqual(self.refused(row), [(0, "members")])
        self.assertIn('unknown member "suiteCommit"', self.repo.lines()[0])

    def test_a_suite_version_member_is_refused(self):
        row = wall_row()
        row["suiteVersion"] = row.pop("kitVersion")
        self.assertEqual(self.refused(row), [(0, "members")])
        line = self.repo.lines()[0]
        self.assertIn('unknown member "suiteVersion"', line)
        self.assertIn("lacks the member kitVersion", line)

    def test_kit_version_kit_2026_11_14_is_refused(self):
        git(self.repo.root, "tag", "kit-2026-11-14")
        self.assertEqual(self.refused(wall_row(kitVersion="kit-2026-11-14")), [(0, "format")])

    def test_kit_version_pseudo_version_is_refused(self):
        pseudo = "v0.0.0-20261112212443-a38e00017076"
        git(self.repo.root, "tag", pseudo)
        self.assertEqual(self.refused(wall_row(kitVersion=pseudo)), [(0, "format")])

    def test_an_absent_tag_is_refused_naming_git_fetch_tags(self):
        self.assertEqual(self.refused(wall_row(kitVersion="v9.9.9")), [(0, "tag")])
        done = self.repo.run()
        self.assertEqual((done.returncode, done.stderr), (1, ""), done.stdout)
        self.assertEqual(done.stdout.splitlines(), [
            'refused: wall/verifiers.json[0] (verifier "Example Verifier"): tag: kitVersion '
            'v9.9.9 is not a tag in this clone: run `git fetch --tags` and check again',
            "wall/verifiers.json: 1 refusal",
        ])

    def test_fixture_count_one_more_than_the_tags_fixtures_is_refused(self):
        row = wall_row(fixtureCount=FIXTURES + 1, agree=FIXTURES + 1)
        self.assertEqual(self.refused(row), [(0, "fixture-count")])

    def test_buckets_that_do_not_sum_to_fixture_count_are_refused(self):
        self.assertEqual(self.refused(wall_row(agree=FIXTURES - 1)), [(0, "sum")])

    def test_accepted_must_fail_1_is_refused(self):
        row = wall_row(agree=FIXTURES - 1, acceptedMustFail=1)
        self.assertEqual(self.refused(row), [(0, "pass")])

    def test_could_not_read_equal_to_fixture_count_is_refused(self):
        row = wall_row(agree=0, couldNotRead=FIXTURES)
        self.assertEqual(self.refused(row), [(0, "pass")])

    def test_a_count_given_as_true_is_refused(self):
        # Read as the integer 1, true would sum to fixtureCount and pass.
        row = wall_row(agree=FIXTURES - 1, rejectedMustPass=True)
        self.assertEqual(self.refused(row), [(0, "format")])

    def test_a_negative_count_is_refused(self):
        row = wall_row(agree=FIXTURES + 1, rejectedMustPass=-1)
        self.assertEqual(self.refused(row), [(0, "format")])

    def test_a_date_one_day_after_today_utc_is_refused(self):
        for _ in range(2):  # a second try when the UTC date turned during the first
            today = utc_today()
            got = self.refused(wall_row(date=(today + ONE_DAY).isoformat()))
            if utc_today() == today:
                break
        self.assertEqual(got, [(0, "date")])

    def test_a_date_before_the_tags_commit_is_refused(self):
        # 2026-11-14 is the commit's date at its own offset; in UTC it is 2026-11-15.
        self.assertEqual(self.refused(wall_row(date="2026-11-14")), [(0, "date")])
        self.assertIn(f"before {RUN_DATE}, the UTC date of the commit", self.repo.lines()[0])

    def test_2026_02_30_is_refused(self):
        self.assertEqual(self.refused(wall_row(date="2026-02-30")), [(0, "format")])

    def test_a_verifier_holding_a_path_is_refused(self):
        self.assertEqual(self.refused(wall_row(verifier="Example /Users/x")), [(0, "format")])

    def test_a_verifier_holding_https_is_refused(self):
        row = wall_row(verifier="Example https://example.invalid")
        self.assertEqual(self.refused(row), [(0, "format")])

    def test_a_verifier_holding_an_at_sign_is_refused(self):
        row = wall_row(verifier="maintainer@example.invalid")
        self.assertEqual(self.refused(row), [(0, "format")])

    def test_a_verifier_of_65_characters_is_refused(self):
        self.assertEqual(self.refused(wall_row(verifier="V" * 64)), [])
        self.assertEqual(self.refused(wall_row(verifier="V" * 65)), [(0, "format")])

    def test_a_version_holding_a_space_is_refused(self):
        self.assertEqual(self.refused(wall_row(version="0.9.1 beta")), [(0, "format")])

    def test_rows_out_of_order_are_refused(self):
        alpha, beta = wall_row(verifier="Alpha Verifier"), wall_row(verifier="Beta Verifier")
        self.assertEqual(self.refused(alpha, beta), [])
        self.assertEqual(self.refused(beta, alpha), [(1, "order")])

    def test_a_duplicate_is_refused(self):
        # The rows differ in their counts only: verifier, version and
        # kitVersion are the key.
        other = wall_row(agree=FIXTURES - 1, rejectedMustPass=1)
        self.assertEqual(self.refused(wall_row(), other), [(1, "unique")])

    def test_a_repeated_key_in_one_row_is_refused(self):
        text = json.dumps([wall_row()])
        self.repo.write("wall/verifiers.json", text[:-2] + f', "agree": {FIXTURES}}}]\n')
        self.assertEqual(self.repo.refusals(), [(0, "repeated-member")])

    def test_a_top_level_that_is_an_object_is_refused(self):
        self.repo.write("wall/verifiers.json", json.dumps(wall_row()) + "\n")
        self.assertEqual(self.repo.refusals(), [(None, "json")])


class AlsoRefused(unittest.TestCase):
    def setUp(self):
        self.repo = Repo(self)

    def test_a_row_that_is_not_an_object_is_refused(self):
        self.repo.admit(wall_row(), ["Example Verifier"])
        self.assertEqual(self.repo.refusals(), [(1, "format")])

    def test_a_count_with_a_fraction_is_refused(self):
        self.repo.admit(wall_row(agree=float(FIXTURES)))
        self.assertEqual(self.repo.refusals(), [(0, "format")])

    def test_counts_summing_to_4301_digits_are_refused_in_one_line(self):
        # JSON reads a count of up to 4300 digits, and Python refuses to write
        # an integer of more, so the sum of these two is never written in full.
        nines = int("9" * 4300)
        self.repo.admit(wall_row(agree=nines, rejectedMustPass=nines))
        self.assertEqual(self.repo.refusals(), [(0, "sum")])
        done = self.repo.run()
        self.assertEqual((done.returncode, done.stderr), (1, ""), done.stdout)
        cut = "9" * 77 + "..."
        self.assertEqual(done.stdout.splitlines(), [
            f'refused: wall/verifiers.json[0] (verifier "Example Verifier"): sum: agree {cut} '
            f"+ acceptedMustFail 0 + rejectedMustPass {cut} + couldNotRead 0 is "
            f"1{'9' * 76}..., not fixtureCount 3: the kit gives each fixture one of the four "
            f"outcomes",
            "wall/verifiers.json: 1 refusal",
        ])

    def test_a_count_of_4300_digits_is_cut_in_each_refusal_that_names_it(self):
        nines = int("9" * 4300)
        self.repo.admit(wall_row(fixtureCount=nines, agree=0, acceptedMustFail=nines,
                                 couldNotRead=nines))
        self.assertEqual(self.repo.refusals(),
                         [(0, "fixture-count"), (0, "sum"), (0, "pass"), (0, "pass")])
        for line in self.repo.lines():
            self.assertIsNone(re.search("[0-9]{78}", line), line[:200])
            self.assertIn("9" * 77 + "...", line)

    def test_a_verifier_ending_in_a_line_break_is_refused(self):
        self.repo.admit(wall_row(verifier="Example Verifier\n"))
        self.assertEqual(self.repo.refusals(), [(0, "format")])

    def test_a_verifier_that_is_an_array_is_named_by_its_kind(self):
        # A refusal line shows an array or an object by its kind, never its
        # contents, so it stays one short line however deep the value nests.
        self.repo.admit(wall_row(verifier=[["Example Verifier"]]))
        self.assertEqual(self.repo.refusals(), [(0, "format")])
        self.assertIn("(verifier (an array)): format: verifier (an array) is not",
                      self.repo.lines()[0])

    def test_a_tag_that_names_no_commit_is_refused(self):
        tree = git(self.repo.root, "rev-parse", "HEAD^{tree}")
        git(self.repo.root, "tag", "-f", TAG, tree)
        self.repo.admit(wall_row())
        self.assertEqual(self.repo.refusals(), [(0, "tag")])

    def test_a_branch_named_as_the_tag_is_refused(self):
        git(self.repo.root, "tag", "-d", TAG)
        git(self.repo.root, "branch", TAG)
        self.repo.admit(wall_row())
        self.assertEqual(self.repo.refusals(), [(0, "tag")])
        self.assertIn("run `git fetch --tags`", self.repo.lines()[0])

    def test_a_file_that_is_not_json_is_refused(self):
        self.repo.write("wall/verifiers.json", "[\n")
        self.assertEqual(self.repo.refusals(), [(None, "json")])

    def test_an_option_without_its_path_exits_2(self):
        for option in ("--file", "--repo"):
            with self.subTest(option):
                done = self.repo.run(option)
                self.assertEqual((done.returncode, done.stdout), (2, ""), done.stderr)
                self.assertTrue(done.stderr.startswith(f"{option} takes a path\nusage: "),
                                done.stderr)


class Contract(unittest.TestCase):
    def test_the_schema_holds_the_members_and_forms_the_check_holds(self):
        from jsonschema import Draft202012Validator

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual(schema["properties"]["$schema"]["const"], schema["$id"])
        row = schema["$defs"]["row"]
        self.assertEqual(row["required"], list(check_wall.ROW_MEMBERS))
        self.assertEqual(list(row["properties"]), list(check_wall.ROW_MEMBERS))
        self.assertIs(row["additionalProperties"], False)
        for name, pattern in check_wall.PATTERNS.items():
            self.assertEqual(row["properties"][name]["pattern"], pattern, name)
        self.assertEqual(
            {name: (row["properties"][name]["type"], row["properties"][name]["minimum"])
             for name in check_wall.COUNTS},
            {name: ("integer", check_wall.LEAST[name]) for name in check_wall.COUNTS})

        validator = Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors([])), [])
        self.assertEqual(list(validator.iter_errors([wall_row()])), [])
        missing = {name: value for name, value in wall_row().items() if name != "date"}
        for label, doc in (
                ("an unknown member", [wall_row(note="run on a laptop")]),
                ("a report member", [wall_row(report="wall/reports/x.json")]),
                ("a missing member", [missing]),
                ("a kit tag as kitVersion", [wall_row(kitVersion="kit-2026-11-14")]),
                ("a pseudo-version as kitVersion",
                 [wall_row(kitVersion="v0.0.0-20261112212443-a38e00017076")]),
                ("a count given as true", [wall_row(rejectedMustPass=True)]),
                ("a negative count", [wall_row(agree=-1)]),
                ("a fixtureCount of 0", [wall_row(fixtureCount=0)]),
                ("a verifier holding a path", [wall_row(verifier="Example /Users/x")]),
                ("a verifier of 65 characters", [wall_row(verifier="V" * 65)]),
                ("a version holding a space", [wall_row(version="0.9.1 beta")]),
                ("a row, not an array of rows", wall_row())):
            with self.subTest(label):
                self.assertTrue(list(validator.iter_errors(doc)), label)

    def test_the_outcome_counts_are_the_kits_summary(self):
        source = REPORT_GO.read_text(encoding="utf-8")
        block = re.search(r"^type Summary struct {\n(.*?)^}", source, re.M | re.S)
        self.assertIsNotNone(block, f"no type Summary struct in {REPORT_GO}")
        self.assertEqual(tuple(re.findall(r'`json:"(\w+)"`', block.group(1))),
                         check_wall.BUCKETS)

    def test_the_fixture_count_is_of_the_set_the_module_embeds(self):
        source = FIXTURES_GO.read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^//go:embed (.*)$", source, re.M), ["fixtures/*.json"])

    def test_the_check_imports_no_network_module(self):
        text = (SCRIPTS / "check_wall.py").read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertLessEqual(imported, STANDARD_MODULES)
        self.assertNotIn("__import__", text)
        self.assertNotIn("importlib", text)

    def test_the_committed_wall_is_an_array_the_schema_admits(self):
        from jsonschema import Draft202012Validator

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        doc = check_wall.read_json(WALL)
        self.assertIsInstance(doc, list)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(doc)), [])


class TheWallsOwnRule(unittest.TestCase):
    """The wall's pass rule, acceptedMustFail 0 and couldNotRead below
    fixtureCount, is not the kit's exit status, which is 0 only when every
    fixture agrees: the wall admits a row from a run on which the kit exited
    1 (#414). Each text that says what passed means on the wall says so."""

    def test_the_kit_exits_0_only_when_every_fixture_agrees(self):
        source = RUN_GO.read_text(encoding="utf-8")
        self.assertIn(KIT_EXIT_GO, source,
                      f"{RUN_GO} does not end a run with the exit status the wall's texts give")
        self.assertIn(plain(KIT_EXIT_USAGE), plain(source))

    def test_a_row_on_which_no_fixture_agreed_is_admitted(self):
        # agree 0 of 3: the kit exits 1 on such a run, and the wall admits it.
        repo = Repo(self)
        repo.admit(wall_row(agree=0, rejectedMustPass=FIXTURES))
        self.assertEqual(repo.refusals(), [])

    def test_each_text_says_the_pass_rule_is_the_walls_own(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        for label, text in (
                ("the docstring of check_wall.py", check_wall.__doc__),
                ("the usage text of check_wall.py", check_wall.USAGE),
                ("wall/README.md", WALL_README.read_text(encoding="utf-8")),
                ("the description of schemas/wall-v1.schema.json", schema["description"])):
            with self.subTest(label):
                words = plain(text)
                missing = [phrase for phrase in (PASS_RULE, NOT_THE_KITS, KIT_EXIT)
                           if plain(phrase) not in words]
                self.assertEqual(missing, [], f"{label} does not say {missing}")

    def test_a_pass_refusal_names_the_walls_rule(self):
        repo = Repo(self)
        repo.admit(wall_row(agree=FIXTURES - 1, acceptedMustFail=1))
        self.assertEqual(repo.refusals(), [(0, "pass")])
        line = repo.lines()[0]
        self.assertIn(": pass: acceptedMustFail is 1: ", line)
        self.assertIn("a row is admitted only at 0", line)
        self.assertNotIn("a run passes", line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
