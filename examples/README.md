# Put your verifier behind the kit's contract

`atx-verify --verifier` and `atx-verify --verifier-url` call your verifier once per fixture and compare its verdicts with `conformance.json`. The two wrappers here fit a verifier to that contract without editing it. Each file's header says what it does and how to run it. `go install` does not fetch these files: copy the one you need next to your verifier, for example with `curl -fsSLO https://raw.githubusercontent.com/opena2a-standards/atx-conformance/<commit>/examples/wrap-verifier.sh` at the suite commit you test against; it runs from any directory. Below, `atx-verify` stands for the kit that `go install github.com/opena2a-standards/atx-conformance/cmd/atx-verify@<commit>` put at `"$(go env GOPATH)/bin/atx-verify"`.

| File | Use with | What it does |
|---|---|---|
| `wrap-verifier.sh` | `--verifier` | Runs your verifier and reads its verdict from the text it prints. |
| `serve_verifier.py` | `--verifier-url` | Serves any command at `http://127.0.0.1:<port>/`. Python 3 standard library only. |

| Adapter | ACCEPT | REJECT | Couldn't read |
|---|---|---|---|
| Command | exit 0 | exit 1 | any other exit, a crash, or a timeout |
| URL | 2xx | 4xx | 5xx, no answer, or a timeout |
| Either, if it prints JSON | `"verdict": "ACCEPT"` or `"valid": true` | `"verdict": "REJECT"` or `"valid": false` | `"verdict": "ERROR"` |

JSON wins over exit and status codes when the whole answer is one JSON object. An optional `"reason"` string is recorded.

## A verifier that prints its verdict as text

Limits first. `{file}` is a whole fixture file: the credential under `atx`, the verifier side (clock, trusted issuers, keys) under `verifierState`. For a verifier that reads a bare credential, put `-` where `{file}` goes and the credential arrives on stdin (or pass `/dev/stdin` as its file). The wrapper checks `REJECT_TEXT` before `ACCEPT_TEXT`, because "invalid" contains "valid"; with neither set it reads the `observed:` line this repository's verifiers print.

    ACCEPT_TEXT=valid REJECT_TEXT=invalid atx-verify --verifier "sh wrap-verifier.sh - my-verifier --check"

## A verifier behind a URL

Limits first. The server listens on 127.0.0.1 only, so only programs on the same machine reach it. It runs your command once per request, `{file}` replaced by a file holding the posted credential, or the credential on stdin when the command has no `{file}`; exit 0 answers 200, exit 1 answers 422, anything else 500, and the command's output is the answer body.

    python3 serve_verifier.py 8080 my-verifier --check {file}
    atx-verify --verifier-url http://127.0.0.1:8080/

What the kit sends: one POST per fixture, the credential JSON alone as the body, `Content-Type: application/json`, `User-Agent: atx-verify`, and an `ATX-Fixture` header naming the fixture file. Nothing that identifies you, no retries, no proxy, and no redirect to another host.

## Why the ATX-Fixture header, and `--fixtures`

The credential alone does not say which fixture it is: `baseline-valid.json`, `revoked-crl-only.json` and `threshold-1of3-cosignature.json` carry the same credential and differ only in the verifier side. Started with `--fixtures DIR`, `serve_verifier.py` hands the command the fixture file the header names, once the posted credential is that fixture's credential (member order, repeated members and number spelling included), and answers couldn't read otherwise. Limit: in that mode it answers only for credentials in the fixture set, and the service learns which fixture it is reading, as a command does from `{file}`.

This repository's Python verifier behind the URL, from a clone with the verifier's packages installed:

    python3 examples/serve_verifier.py 8765 --fixtures fixtures sh examples/wrap-verifier.sh {file} python3 verifiers/python/verify.py
    go run ./cmd/atx-verify --verifier-url http://127.0.0.1:8765/

`go test ./examples/` runs both wrappers against the Go and the Python verifier, and sends every fixture in `conformance.json` through the URL adapter to the Python verifier behind `serve_verifier.py`. Set `ATX_PYTHON` to an interpreter that has the Python verifier's packages; without them those two tests are skipped and say why.
