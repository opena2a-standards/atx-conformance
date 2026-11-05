#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Puts any verifier command behind the kit's URL contract on 127.0.0.1: exit 0 answers 200 (ACCEPT), exit 1 answers 422 (REJECT), anything else 500.
# Run: python3 serve_verifier.py 8080 [--fixtures DIR] <your command, {file} for the posted credential>, then atx-verify --verifier-url http://127.0.0.1:8080/
import json, os, subprocess, sys, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USAGE = "usage: serve_verifier.py <port> [--fixtures DIR] <command...>  ({file} in the command is the posted credential; without it, stdin is)"


def tree(raw):  # JSON as data that keeps member order, repeated members and number spelling
    return json.loads(raw, object_pairs_hook=lambda p: ("o", p), parse_int=lambda s: ("n", s), parse_float=lambda s: ("n", s), parse_constant=lambda s: ("c", s))


def fixture_for(body, name):  # the fixture file the ATX-Fixture header names, when its credential is the one posted
    path = os.path.join(FIXTURES, os.path.basename(name))
    try:
        with open(path, "rb") as f:
            return path if dict(tree(f.read())[1])["atx"] == tree(body) else None
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "credential.json")
            with open(path, "wb") as f:
                f.write(body)
            if FIXTURES:
                path = fixture_for(body, self.headers.get("ATX-Fixture", ""))
                if path is None:
                    return self.answer(500, {"verdict": "ERROR", "reason": "the posted credential is not the credential of the fixture its ATX-Fixture header names"})
            argv = [a.replace("{file}", path) for a in COMMAND]
            try:
                run = subprocess.run(argv, input=body if argv == COMMAND else b"", capture_output=True, timeout=60)
            except (OSError, subprocess.TimeoutExpired) as e:
                return self.answer(500, {"verdict": "ERROR", "reason": str(e)})
        self.answer({0: 200, 1: 422}.get(run.returncode, 500), run.stdout or run.stderr)

    def answer(self, status, body):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    PORT, COMMAND, FIXTURES = sys.argv[1:2], sys.argv[2:], None
    if COMMAND[:1] == ["--fixtures"]:
        FIXTURES, COMMAND = (COMMAND[1:2] or [None])[0], COMMAND[2:]
    if not (PORT and PORT[0].isdigit() and COMMAND and FIXTURES != ""):
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    server = ThreadingHTTPServer(("127.0.0.1", int(PORT[0])), Handler)
    print("listening on http://127.0.0.1:%d/" % server.server_port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
