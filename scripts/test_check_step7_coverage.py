#!/usr/bin/env python3
"""The module docstring of check_step7_coverage.py names the file that says
conformance.json's notCovered and the Coverage paragraph of core.md drop
section 1.3 step 7 together, and that file holds the sentence.

Before the change this test came with, the docstring said "the README says
the two drop it together", and README.md holds no such sentence. It is in
docs/fixtures.md, in the section "Required trust level: the distinct
signer-authority count".

The test reads the script's source and the file its docstring names; it runs
neither. Run from the repository root:

    python3 scripts/test_check_step7_coverage.py
"""

import ast
import pathlib
import re
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
SCRIPT = SCRIPTS / "check_step7_coverage.py"
SENTENCE = "the two drop it together"
# The clause of the docstring that names the file: `<path> says the two drop
# it together`, the path written plain or in backticks, relative to the
# repository root.
CITATION = re.compile(r"`?([\w./-]+)`? says " + re.escape(SENTENCE))


def one_line(text):
    """text with each run of white space read as one space, as a sentence
    wrapped over several lines reads."""
    return " ".join(text.split())


class DocstringCitation(unittest.TestCase):
    def test_the_file_the_docstring_names_holds_the_sentence(self):
        doc = ast.get_docstring(ast.parse(SCRIPT.read_text(encoding="utf-8")))
        self.assertIsNotNone(doc, f"{SCRIPT.name} has no module docstring")
        cited = CITATION.findall(one_line(doc))
        self.assertEqual(len(cited), 1,
                         f"want one `<path> says {SENTENCE}` clause in the docstring "
                         f"of {SCRIPT.name}, found {cited}")
        path = ROOT / cited[0]
        self.assertTrue(path.is_file(),
                        f"the docstring of {SCRIPT.name} names {cited[0]} as saying "
                        f"{SENTENCE!r}, but the repository root holds no file {cited[0]}")
        self.assertIn(SENTENCE, one_line(path.read_text(encoding="utf-8")),
                      f"the docstring of {SCRIPT.name} names {cited[0]} as saying "
                      f"{SENTENCE!r}, but {cited[0]} does not say it")


if __name__ == "__main__":
    unittest.main()
