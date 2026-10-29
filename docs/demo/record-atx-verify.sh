#!/usr/bin/env bash
# Renders docs/demo/atx-verify.tape inside the render container and writes its sidecar.
#
#   docs/demo/record-atx-verify.sh
#   DOCKER=<path to the docker binary> docs/demo/record-atx-verify.sh
#   docs/demo/record-atx-verify.sh --dry-run
#
# The tape types the README's first command, `go run <module>/cmd/atx-verify@latest`, in an empty
# directory. The recording therefore shows the module version the Go module proxy names for @latest
# when it runs, which is the build a new user gets, and not this checkout. The sidecar records that
# version and the commit it was built from, and says `prerelease: false` only when HEAD of this
# checkout carries the tag of that same version.
#
# The image (docs/demo/docker/Dockerfile) carries VHS 0.12.0 with its encode regression patched,
# ttyd, ffmpeg, Chromium, JetBrains Mono, gifsicle, python3 and a Go toolchain. It is built from two
# images named by the digest of their image index and from the VHS source at one commit; the script
# reads those pins from the Dockerfile, refuses one that names an image by tag alone or the source
# by no commit, and the sidecar's `recorder` records them as the Dockerfile writes them. The
# container's hostname is `laptop` and its home directory /work/demo-user starts empty, so the Go
# module and build caches start empty too. It runs with --cap-drop ALL, --security-opt
# no-new-privileges and --pids-limit 256, and with the network: the tape's command resolves the
# module through the Go module proxy, so a render with no network would record another command, and
# the sidecar lists --network none as dropped, with that reason. docs/demo is mounted into it
# read-only, at /work/input/docs/demo, and the render writes into a new empty directory mounted at
# /work/docs/demo. It receives no variable of the calling environment other than the ones this
# script names. In the container the script:
#   1. asks the module proxy which version @latest names (`go list -m -json`);
#   2. renders the tape: atx-verify.gif, out/atx-verify.mp4 and one PNG per step;
#   3. runs the typed commands once more with NO_COLOR=1 TERM=dumb COLUMNS=110 into
#      atx-verify-capture.txt, the text version of the recording. Each command runs in a new bash
#      whose $? is the exit code of the command before it, so `echo $?` prints what it printed on
#      screen;
#   4. checks that one version of the module was downloaded and that `atx-verify --version` names it,
#      and reads the commit it was built from out of the .info file the proxy served for it;
#   5. optimises the GIF with gifsicle -O3 --lossy=40 and moves the MP4's index to the front;
#   6. checks the pace rule (P1-P8) against the tape, the capture, the narration and the outputs;
#   7. writes the version into atx-verify.narration.json and writes atx-verify.json (schema
#      demo-sidecar/2).
# A render whose first command does not exit 0 with a `summary:` line last, or that breaks the pace
# rule, writes no sidecar and exits 3. After a render that wrote the sidecar, this script copies the
# files the tape names, the capture, the narration (when its version changed) and the sidecar from
# the render's directory into docs/demo, the sidecar last; it copies nothing when that directory
# holds a link or one of those is not a regular file. The outputs, the capture and the sidecar of an
# earlier render are removed from docs/demo before the container starts, so a render that stops part
# way leaves none of them there and copies nothing; the script then names the directory that holds
# what the render wrote. The MP4 goes to docs/demo/out/, which is not committed.
#
# docker build and docker run use a configuration directory of this script's own, removed when the
# script ends, which names no credential helper and holds no registry credentials; the base images
# are public and are pulled by digest. The caller's configuration can name a helper that reads the
# OS keychain. The endpoint of the docker context in use is carried over as DOCKER_HOST, and the
# caller's plugin directory and Docker Desktop's (when present) as cliPluginsExtraDirs, so buildx is
# still found.
#
# --dry-run prints the image, its base images, the VHS source, the container's flags, the tape, the
# checkout and the files a render writes, then exits 0. It runs git and no docker command, and
# writes no file. Like a render, it exits 1 when the Dockerfile names a base image by tag alone or
# the VHS source by no commit.
#
# Nothing metered is called: VHS, Go, the Go module proxy and the checksum database are free to use.
set -euo pipefail

NAME="atx-verify"
MODULE="github.com/opena2a-standards/atx-conformance"
FRONT_DOOR="/work/front-door"
TAPE="docs/demo/$NAME.tape"

if [ "$#" -eq 1 ] && [ "$1" = "--in-container" ]; then
  exec python3 -I - "$NAME" "$MODULE" "$FRONT_DOOR" <<'PY'
import hashlib, json, math, os, re, socket, subprocess, sys, time

NAME, MODULE, FRONT_DOOR = sys.argv[1:4]
os.chdir('/work')
# The paths are the checkout's. What the render writes goes to /work/docs/demo, the new empty directory
# the host side copies into docs/demo; the checkout's docs/demo is mounted read-only at
# /work/input/docs/demo, and mounted() names an input's copy there.
DEMO = 'docs/demo'
TAPE = f'{DEMO}/{NAME}.tape'
NARRATION = f'{DEMO}/{NAME}.narration.json'
CAPTURE = f'{DEMO}/{NAME}-capture.txt'
SIDECAR = f'{DEMO}/{NAME}.json'
PATCH = f'{DEMO}/docker/vhs-0.12.0-render-context.patch'
RECORD = f'{DEMO}/record-{NAME}.sh'
TITLES = {'s1': "Run the README's first command", 's2': 'Print the exit code'}
# The container's limits. Each one either ran, as the host side passes it in RUN_FLAGS, or is written
# here with the reason the render goes without it; a limit that is neither stops the render.
LIMITS = ('--network none', '--cap-drop ALL', '--security-opt no-new-privileges', '--pids-limit 256')
DROPPED = [{'flag': '--network none',
            'reason': f"the tape types the README's first command, `go run {MODULE}/cmd/{NAME}@latest`, which "
                      'resolves the module through the Go module proxy that environment.goproxy names; with no '
                      'network the recording would show another command'}]
# The pace rule as numbers. P1 typing speed and typed line length, P2 the hold before Enter, P3 the
# hold on output (sized from the rows on screen and the narration at 150 words a minute), P4 no
# scrolling or cut inside output, P5 no blinking cursor, P6 length, P7 framing, P8 formats and size.
PACE = {'typingMs': (100, 140), 'maxLineChars': 72, 'preEnterMs': (600, 1000), 'floorSeconds': 3,
        'rowsPerSecond': 4, 'wordsPerMinute': 150, 'padSeconds': 0.5, 'maxHoldSeconds': 12,
        'maxSeconds': {'front-door': 45, 'multi-step': 90}, 'columns': (100, 120), 'rows': (24, 30),
        'fontSize': (14, 16), 'padding': 20, 'gifFramerate': 10, 'mp4Fps': (24, 30),
        'gifMaxBytes': 3_000_000, 'gifMaxWidth': 1200, 'videoBytesPerMinute': 5_000_000}


def fail(message, code=1):
    print(f'record-{NAME}.sh: {message}', file=sys.stderr)
    sys.exit(code)


def run(*args, cwd=None):
    proc = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        fail(f'`{" ".join(args)}` exited {proc.returncode}; nothing more was written.')
    return proc.stdout.strip()


def sha256(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def mounted(path):
    return f'/work/input/{path}'


def pinned(variable):
    """An image the Dockerfile names by the digest of its index, as its reference and that digest."""
    ref, _, digest = os.environ.get(variable, '').partition('@')
    return {'ref': ref or None, 'digest': digest or None}


def tidy(x):
    return int(x) if float(x).is_integer() else round(x, 2)


def probe(path):
    found = json.loads(run('ffprobe', '-v', 'error', '-count_frames', '-select_streams', 'v:0', '-show_entries',
                           'stream=width,height,nb_read_frames,codec_name,pix_fmt,r_frame_rate:format=duration',
                           '-of', 'json', path))
    stream = found['streams'][0]
    return stream, float(found['format']['duration'])


def png_size(path):
    with open(path, 'rb') as f:
        head = f.read(24)
    if head[:8] != b'\x89PNG\r\n\x1a\n':
        fail(f'{path} is not a PNG file.')
    return int.from_bytes(head[16:20], 'big'), int.from_bytes(head[20:24], 'big')


def top_level_atoms(path):
    names, size_left = [], os.path.getsize(path)
    with open(path, 'rb') as f:
        while size_left >= 8:
            head = f.read(8)
            size, kind = int.from_bytes(head[:4], 'big'), head[4:].decode('latin-1')
            names.append(kind)
            if size == 1:
                size = int.from_bytes(f.read(8), 'big')
                f.seek(size - 16, 1)
            elif size == 0 or size < 8:
                break
            else:
                f.seek(size - 8, 1)
            size_left -= size
    return names


def parse_tape(text):
    """The tape's settings, its hidden typed text, and its shown commands in order."""
    tape = {'settings': {}, 'outputs': [], 'requires': [], 'screenshots': [], 'hidden': [], 'events': [],
            'kind': None, 'problems': []}
    hidden = shown = False
    for n, raw in enumerate(text.split('\n'), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith('#'):
            step = re.fullmatch(r'#\s*step:\s*(\S+)', line)
            kind = re.fullmatch(r'#\s*Pace:\s*(\S+)', line)
            if step:
                tape['events'].append(('step', step.group(1), n))
            elif kind:
                tape['kind'] = kind.group(1)
            continue
        word, _, rest = line.partition(' ')
        rest = rest.strip()
        if word == 'Set':
            key, _, value = rest.partition(' ')
            tape['settings'][key] = value.strip().strip('"')
        elif word == 'Output':
            tape['outputs'].append(rest)
        elif word == 'Require':
            tape['requires'].append(rest)
        elif word == 'Hide':
            if shown:
                tape['problems'].append(f'{TAPE}:{n}: a Hide after Show cuts inside the recording (P4: hidden set-up only before the first Show)')
            hidden = True
        elif word == 'Show':
            hidden, shown = False, True
        elif word.startswith('Type'):
            typed = re.fullmatch(r'Type(?:@(\d+)ms)?\s+(["\'`])(.*)\2', line)
            if not typed:
                tape['problems'].append(f'{TAPE}:{n}: a Type line this script cannot read')
                continue
            speed = int(typed.group(1)) if typed.group(1) else None
            if hidden:
                tape['hidden'].append((typed.group(3), n))
            else:
                tape['events'].append(('type', typed.group(3), n, speed))
        elif word == 'Sleep':
            sleep = re.fullmatch(r'(\d+(?:\.\d+)?)(ms|s)', rest)
            if not sleep:
                tape['problems'].append(f'{TAPE}:{n}: a Sleep this script cannot read')
            elif not hidden:
                tape['events'].append(('sleep', float(sleep.group(1)) * (1 if sleep.group(2) == 'ms' else 1000), n))
        elif word == 'Enter':
            if rest:
                tape['problems'].append(f'{TAPE}:{n}: Enter with a count or speed; press Enter once per command')
            if not hidden:
                tape['events'].append(('enter', None, n))
        elif word == 'Screenshot':
            tape['screenshots'].append(rest)
            if not hidden:
                tape['events'].append(('screenshot', rest, n))
        elif re.match(r'(Scroll|PageUp|PageDown)', word) and not hidden:
            tape['problems'].append(f'{TAPE}:{n}: {word} moves the screen inside the output (P4)')
    return tape


def measure(tape):
    """Steps: each `# step:` line, the lines typed after it, every Enter with the Sleep just before it,
    and the hold, the Sleeps after the step's last Enter until the next Type or step."""
    steps, enters, problems = [], [], []
    current, previous = None, None
    for event in tape['events']:
        kind = event[0]
        if kind == 'step':
            current = {'id': event[1], 'typed': [], 'holdMs': 0.0, 'entered': False, 'anchorFrame': None}
            steps.append(current)
        elif kind == 'type':
            if current is None:
                problems.append(f'{TAPE}:{event[2]}: a line is typed before the first `# step:` line')
            else:
                if current['entered'] and not current['typed'][-1][0].endswith('\\'):
                    problems.append(f'{TAPE}:{event[2]}: step {current["id"]} types a second command; a step types one command (a long one continues with a backslash)')
                current['typed'].append((event[1], event[2], event[3]))
                current['entered'], current['holdMs'] = False, 0.0
        elif kind == 'sleep':
            if current is not None and current['entered']:
                current['holdMs'] += event[1]
        elif kind == 'enter':
            enters.append((event[2], previous[1] if previous and previous[0] == 'sleep' else None))
            if current is not None:
                current['entered'], current['holdMs'] = True, 0.0
        elif kind == 'screenshot':
            if current is not None and current['entered']:
                current['anchorFrame'] = event[1]
        previous = event
    for step in steps:
        if not step['typed'] or not step['entered']:
            problems.append(f'{TAPE}: step {step["id"]} types no command and presses Enter after it')
        elif step['typed'][-1][0].endswith('\\'):
            problems.append(f'{TAPE}:{step["typed"][-1][1]}: step {step["id"]} ends on a continuation')
        step['command'] = ''.join(t[:-1] if t.endswith('\\') else t for t, _n, _s in step['typed'])
    return steps, enters, problems


if socket.gethostname() != 'laptop':
    fail(f'the hostname is {socket.gethostname()}, not laptop; not recording.')
with open(mounted(TAPE), encoding='utf-8') as f:
    tape = parse_tape(f.read())
if not any(f'cd {FRONT_DOOR}' in text for text, _n in tape['hidden']):
    fail(f'the hidden set-up of {TAPE} does not enter {FRONT_DOOR}; not recording.')
steps, enters, problems = measure(tape)
problems = tape['problems'] + problems
commands = [step['command'] for step in steps]
with open(mounted(NARRATION), encoding='utf-8') as f:
    narration = json.load(f)
# The limits the container runs with, as the host side ran them, and the ones it goes without.
ran_flags = re.findall(r'--\S+(?: (?!--)\S+)?', os.environ.get('RUN_FLAGS', ''))
dropped = [d for d in DROPPED if d['flag'] not in ran_flags]
unaccounted = [flag for flag in LIMITS if flag not in ran_flags and flag not in [d['flag'] for d in dropped]]
if unaccounted:
    fail(f'the container runs without {", ".join(unaccounted)}, and {RECORD} gives no reason for it in DROPPED; '
         'not recording.')
os.makedirs(f'{DEMO}/out', exist_ok=True)
os.makedirs(os.environ['HOME'], exist_ok=True)

latest = json.loads(run('go', 'list', '-m', '-json', f'{MODULE}@latest'))
version = latest['Version']
ran_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
started = time.monotonic()
if subprocess.run(['vhs', mounted(TAPE)], stdin=subprocess.DEVNULL).returncode != 0:
    fail(f'vhs {TAPE} failed; no sidecar was written.')
wall_clock = round(time.monotonic() - started, 1)
for path in tape['outputs'] + tape['screenshots']:
    if not os.path.isfile(path):
        fail(f'the render wrote no {path}; no sidecar was written.')

# The text version: the typed commands once more, in the directory the tape ran them in.
if not os.path.isdir(FRONT_DOOR):
    fail(f'the hidden set-up of {TAPE} did not create {FRONT_DOOR}; no sidecar was written.')
columns = int(tape['settings'].get('Columns', '0'))
env = dict(os.environ, NO_COLOR='1', TERM='dumb', COLUMNS=str(columns))
capture, outputs, exit_codes, code = [], [], [], 0
for command in commands:
    proc = subprocess.run(['bash', '--noprofile', '--norc', '-c', '(exit "$PREVIOUS_EXIT_CODE"); eval "$TYPED_COMMAND"'],
                          cwd=FRONT_DOOR, env=dict(env, PREVIOUS_EXIT_CODE=str(code), TYPED_COMMAND=command),
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        printed = proc.stdout.decode('utf-8')
    except UnicodeDecodeError:
        fail(f'`{command}` printed bytes that are not UTF-8; no sidecar was written.', 3)
    code = proc.returncode
    exit_codes.append(code)
    outputs.append(printed)
    capture.append(f'$ {command}\n{printed}')
with open(CAPTURE, 'w', encoding='utf-8') as f:
    f.write(''.join(capture))
last = [line for line in outputs[0].split('\n') if line.strip()][-1:] if outputs else []
if not exit_codes or exit_codes[0] != 0 or not last or not last[0].startswith('summary: '):
    first = commands[0] if commands else '(no command)'
    printed_last = repr(last[0]) if last else 'nothing'
    fail(f'`{first}` exited {exit_codes[0] if exit_codes else "-"} and printed {printed_last} last, not a summary '
         f'line after exit 0; no sidecar was written (see {NAME}-capture.txt in the directory named below).', 3)

# One module version served the hidden set-up, the recording and the capture, and it is the version
# `go list` named before the render and `atx-verify --version` names after it.
version_line = run('go', 'run', f'{MODULE}/cmd/{NAME}@latest', '--version', cwd=FRONT_DOOR)
reported = re.fullmatch(rf'{re.escape(NAME)}: (\S+) (\S+), built with (\S+)', version_line)
if not reported or reported.group(1) != MODULE or reported.group(2) != version:
    fail(f'`{NAME} --version` printed {version_line!r}; `go list` named {MODULE} {version}. @latest moved during the render; run again.')
module_cache = run('go', 'env', 'GOMODCACHE')
owner = os.path.join(module_cache, *MODULE.split('/')[:-1])
downloaded = sorted(d for d in os.listdir(owner) if d.startswith(MODULE.split('/')[-1] + '@'))
if downloaded != [f'{MODULE.split("/")[-1]}@{version}']:
    fail(f'the module cache holds {downloaded}, not one copy of {version}. @latest moved during the render; run again.')
manifest = os.path.join(owner, downloaded[0], 'MANIFEST.sha256')
# The commit the version was built from, as the module proxy served it in the version's .info file
# (`go list -m` leaves it out); a pseudo-version ends in that commit's first twelve hex digits.
with open(os.path.join(module_cache, 'cache', 'download', MODULE, '@v', f'{version}.info'), encoding='utf-8') as f:
    origin = json.load(f).get('Origin') or {}
commit = origin.get('Hash')
abbreviated = re.search(r'\d{14}-([0-9a-f]{12})$', version)
if commit and abbreviated and not commit.startswith(abbreviated.group(1)):
    fail(f'the module proxy names commit {commit} for {version}, which ends in another commit; no sidecar was written.')
module_sum = json.loads(run('go', 'mod', 'download', '-json', f'{MODULE}@{version}')).get('Sum')

# The GIF for the README, optimised; the MP4 with its index first, for the website.
gif_path = next(p for p in tape['outputs'] if p.endswith('.gif'))
mp4_path = next(p for p in tape['outputs'] if p.endswith('.mp4'))
run('gifsicle', '-O3', '--lossy=40', '--batch', gif_path)
run('ffmpeg', '-loglevel', 'error', '-y', '-i', mp4_path, '-c', 'copy', '-movflags', '+faststart', mp4_path + '.faststart.mp4')
os.replace(mp4_path + '.faststart.mp4', mp4_path)
gif_stream, gif_seconds = probe(gif_path)
mp4_stream, mp4_seconds = probe(mp4_path)
atoms = top_level_atoms(mp4_path)
faststart = 'moov' in atoms and 'mdat' in atoms and atoms.index('moov') < atoms.index('mdat')
num, den = (int(x) for x in mp4_stream['r_frame_rate'].split('/'))
mp4_fps = num / den if den else 0

# The pace rule.
settings = tape['settings']


def setting(key):
    try:
        return float(settings[key].removesuffix('ms'))
    except (KeyError, ValueError):
        return None


def within(value, bounds):
    return value is not None and bounds[0] <= value <= bounds[1]


typing = setting('TypingSpeed')
screen_rows = int(setting('Rows') or 0)
if not within(typing, PACE['typingMs']):
    problems.append(f'{TAPE}: Set TypingSpeed {settings.get("TypingSpeed")} (P1: {PACE["typingMs"][0]}-{PACE["typingMs"][1]}ms)')
typed_lines = [t for step in steps for t in step['typed']]
for text, n, speed in typed_lines:
    if speed is not None and not within(speed, PACE['typingMs']):
        problems.append(f'{TAPE}:{n}: types at {speed}ms a character (P1)')
    if len(text) > PACE['maxLineChars']:
        problems.append(f'{TAPE}:{n}: a typed line of {len(text)} characters (P1: at most {PACE["maxLineChars"]})')
    if '|' in text or text.startswith('#'):
        problems.append(f'{TAPE}:{n}: a typed line is piped or is a comment: {text}')
for text, n in tape['hidden'] + [(t, n) for t, n, _s in typed_lines]:
    if re.search(r'/Users/|~/|\$HOME\b', text):
        problems.append(f'{TAPE}:{n}: typed text names a home directory')
for text, n in tape['hidden']:
    for part in re.split(r'&&|\|\||;', text):
        if re.match(r'\s*(cat|less|more|echo)\b', part):
            problems.append(f'{TAPE}:{n}: the hidden set-up prints text with `{part.split()[0]}` (P4: Hide never substitutes output)')
for command in commands:
    binary = command.split()[0]
    builtin = subprocess.run(['bash', '-c', 'type -t "$1"', 'bash', binary], stdout=subprocess.PIPE, text=True).stdout.strip()
    if binary not in tape['requires'] and builtin not in ('builtin', 'keyword'):
        problems.append(f'{TAPE}: no Require line for {binary}')
for n, before in enters:
    if not within(before, PACE['preEnterMs']):
        problems.append(f'{TAPE}:{n}: Enter after {"no Sleep" if before is None else f"a Sleep of {tidy(before)}ms"} (P2: {PACE["preEnterMs"][0]}-{PACE["preEnterMs"][1]}ms)')
words_per_second = PACE['wordsPerMinute'] / 60
texts = {s.get('id'): s.get('text', '') for s in narration.get('steps', [])}
if narration.get('schema') != 'demo-narration/1' or narration.get('tool') != NAME or narration.get('wordsPerMinute') != PACE['wordsPerMinute']:
    problems.append(f'{NARRATION}: needs schema demo-narration/1, tool {NAME} and wordsPerMinute {PACE["wordsPerMinute"]}')
if list(texts) != [step['id'] for step in steps]:
    problems.append(f'{NARRATION}: narrates steps {list(texts)}, the tape has {[step["id"] for step in steps]}')
for step, printed in zip(steps, outputs):
    rows = sum(max(1, math.ceil(len(line) / columns)) for line in printed.rstrip('\n').split('\n')) if printed else 0
    words = len(texts.get(step['id'], '').split())
    need = max(PACE['floorSeconds'], min(rows, screen_rows) / PACE['rowsPerSecond'],
               words / words_per_second + PACE['padSeconds'] if words else 0)
    step.update(outputRows=rows, narrationWords=words, minHoldSeconds=round(need, 2), holdSeconds=step['holdMs'] / 1000)
    if step['holdSeconds'] + 1e-9 < need:
        problems.append(f'{TAPE}: step {step["id"]} holds {tidy(step["holdSeconds"])} s; P3 needs at least {round(need, 2)} s ({rows} rows of output, {words} narration words)')
    if step['holdSeconds'] > PACE['maxHoldSeconds']:
        problems.append(f'{TAPE}: step {step["id"]} holds {tidy(step["holdSeconds"])} s (P3: at most {PACE["maxHoldSeconds"]} s a screen)')
    if step['anchorFrame'] is None:
        problems.append(f'{TAPE}: step {step["id"]} takes no Screenshot after its Enter, so it has no anchor frame')
if settings.get('CursorBlink') != 'false':
    problems.append(f'{TAPE}: does not Set CursorBlink false (P5)')
limit = PACE['maxSeconds'].get(tape['kind'])
if limit is None:
    problems.append(f'{TAPE}: declares no `# Pace: front-door` or `# Pace: multi-step` line')
elif max(gif_seconds, mp4_seconds) > limit:
    problems.append(f'the recording runs {round(max(gif_seconds, mp4_seconds), 2)} s (P6: a {tape["kind"]} recording at most {limit} s)')
for key, bounds in (('Columns', PACE['columns']), ('Rows', PACE['rows']), ('FontSize', PACE['fontSize'])):
    if not within(setting(key), bounds):
        problems.append(f'{TAPE}: Set {key} {settings.get(key)} (P7: {bounds[0]}-{bounds[1]})')
if setting('Padding') != PACE['padding'] or setting('Framerate') != PACE['gifFramerate']:
    problems.append(f'{TAPE}: Set Padding {settings.get("Padding")} and Framerate {settings.get("Framerate")} (P7: {PACE["padding"]} and {PACE["gifFramerate"]})')
if not within(mp4_fps, PACE['mp4Fps']):
    problems.append(f'{mp4_path}: {mp4_stream["r_frame_rate"]} frames a second (P7: {PACE["mp4Fps"][0]}-{PACE["mp4Fps"][1]})')
gif_bytes, mp4_bytes = os.path.getsize(gif_path), os.path.getsize(mp4_path)
if gif_bytes > PACE['gifMaxBytes'] or int(gif_stream['width']) > PACE['gifMaxWidth']:
    problems.append(f'{gif_path}: {gif_bytes} bytes, {gif_stream["width"]} px wide (P8: at most {PACE["gifMaxBytes"]} bytes and {PACE["gifMaxWidth"]} px)')
if mp4_stream['codec_name'] != 'h264' or mp4_stream['pix_fmt'] != 'yuv420p' or not faststart \
        or mp4_bytes / (mp4_seconds / 60) > PACE['videoBytesPerMinute']:
    problems.append(f'{mp4_path}: {mp4_stream["codec_name"]} {mp4_stream["pix_fmt"]}, index first {faststart}, {mp4_bytes} bytes for {round(mp4_seconds, 2)} s (P8: h264 yuv420p, index first, at most {PACE["videoBytesPerMinute"]} bytes a minute)')
if problems:
    print(f'record-{NAME}.sh: the render breaks the pace rule; no sidecar was written:', file=sys.stderr)
    for problem in problems:
        print(f'  {problem}', file=sys.stderr)
    print(f'Change {TAPE} or {NARRATION} as each line says, then run docs/demo/record-{NAME}.sh again.', file=sys.stderr)
    sys.exit(3)

# The narration names the version it was recorded with; its words are left as they are.
if narration.get('version') != version:
    narration['version'] = version
    with open(NARRATION, 'w', encoding='utf-8') as f:
        f.write(json.dumps(narration, indent=2) + '\n')

head_tags = os.environ.get('HEAD_TAGS', '').split()
with open('/etc/os-release', encoding='utf-8') as f:
    os_name = next((line.split('=', 1)[1].strip().strip('"') for line in f if line.startswith('PRETTY_NAME=')), None)
frames = []
for path in tape['screenshots']:
    width, height = png_size(path)
    frames.append({'path': path, 'bytes': os.path.getsize(path), 'sha256': sha256(path), 'width': width, 'height': height})
sidecar = {
    'schema': 'demo-sidecar/2',
    'surfaceClass': 'terminal',
    'tool': NAME,
    'version': version,
    'commit': commit,
    'prerelease': version not in head_tags,
    'script': TAPE,
    'scriptSha256': sha256(mounted(TAPE)),
    'recorder': {'name': 'vhs', 'version': run('vhs', '--version').split()[-1], 'container': f'{DEMO}/docker/Dockerfile',
                 'patch': PATCH, 'image': os.environ.get('IMAGE'), 'imageId': os.environ.get('IMAGE_ID'),
                 'baseImage': dict(pinned('BASE_IMAGE'), version=os.environ.get('BASE_VERSION') or None,
                                   revision=os.environ.get('BASE_REVISION') or None),
                 'builderImage': dict(pinned('BUILDER_IMAGE'), go=run('go', 'env', 'GOVERSION')),
                 'source': {'repository': os.environ.get('SOURCE_REPOSITORY') or None,
                            'tag': os.environ.get('SOURCE_TAG') or None, 'commit': os.environ.get('SOURCE_COMMIT') or None},
                 'runFlags': ran_flags, 'droppedFlags': dropped},
    'commands': commands,
    'steps': [{'id': s['id'], 'title': TITLES.get(s['id'], s['id']), 'anchorFrame': s['anchorFrame'],
               'holdSeconds': tidy(s['holdSeconds']), 'minHoldSeconds': tidy(s['minHoldSeconds']),
               'outputRows': s['outputRows'], 'narrationWords': s['narrationWords']} for s in steps],
    'fixture': f'fixtures/*.json built into {MODULE}@{version}, read by {NAME} run with no argument in an empty directory',
    'fixtureSha': sha256(manifest),
    'fixtureUncommittedChanges': 0,
    'ranAtUtc': ran_at,
    'durationSeconds': tidy(round(gif_seconds, 2)),
    'outputs': {
        'gif': {'path': gif_path, 'bytes': gif_bytes, 'sha256': sha256(gif_path), 'width': gif_stream['width'],
                'height': gif_stream['height'], 'frames': int(gif_stream.get('nb_read_frames', 0))},
        'mp4': {'path': mp4_path, 'bytes': mp4_bytes, 'sha256': sha256(mp4_path), 'width': mp4_stream['width'],
                'height': mp4_stream['height'], 'frames': int(mp4_stream.get('nb_read_frames', 0)),
                'durationSeconds': tidy(round(mp4_seconds, 2)), 'codec': mp4_stream['codec_name'],
                'pixFmt': mp4_stream['pix_fmt'], 'frameRate': mp4_stream['r_frame_rate'], 'faststart': faststart,
                'committed': False},
        'frames': frames,
    },
    'capture': CAPTURE,
    'narration': NARRATION,
    'pace': {'typingSpeedMs': tidy(typing), 'preEnterHoldMs': tidy(min(b for _n, b in enters)),
             'minHoldSeconds': tidy(min(s['holdSeconds'] for s in steps)),
             'maxLineChars': max(len(t) for t, _n, _s in typed_lines), 'kind': tape['kind']},
    'exitCodes': exit_codes,
    'meteredCostUsd': 0,
    'typedLines': [t for t, _n, _s in typed_lines],
    'module': {'path': MODULE, 'query': 'latest', 'version': version, 'time': latest.get('Time'),
               'origin': origin or None, 'sum': module_sum, 'versionLine': version_line},
    'fixtureShaOf': f'MANIFEST.sha256 of {MODULE}@{version}, from the Go module proxy',
    'recordScript': RECORD,
    'recordScriptSha256': sha256(mounted(RECORD)),
    'fixturePath': FRONT_DOOR,
    'homePath': os.environ['HOME'],
    'hostname': socket.gethostname(),
    'columns': columns,
    'rows': screen_rows,
    'framerate': int(setting('Framerate')),
    'gifsicle': '-O3 --lossy=40 --batch',
    'wallClockSeconds': wall_clock,
    'vhsPatchSha256': sha256(mounted(PATCH)),
    'edits': ['set-up not shown: the hidden set-up enters an empty directory and runs the command once, so the module is downloaded and built before the first frame'],
    'environment': {'os': os_name, 'go': run('go', 'version'), 'goproxy': run('go', 'env', 'GOPROXY'),
                    'gosumdb': run('go', 'env', 'GOSUMDB'), 'gotoolchain': run('go', 'env', 'GOTOOLCHAIN')},
}
if sidecar['commit'] is None:
    del sidecar['commit']
with open(SIDECAR, 'w', encoding='utf-8') as f:
    f.write(json.dumps(sidecar, indent=2) + '\n')
holds = ', '.join('%s %s s (P3 at least %s s)' % (s['id'], tidy(s['holdSeconds']), tidy(s['minHoldSeconds'])) for s in steps)
print(f'rendered: {NAME} {version}, prerelease {str(sidecar["prerelease"]).lower()}, durationSeconds {sidecar["durationSeconds"]}, '
      f'gif {gif_bytes} bytes {gif_stream["width"]}x{gif_stream["height"]}, mp4 {mp4_bytes} bytes, holds {holds}, '
      f'exit codes {exit_codes}, meteredCostUsd 0, wallClockSeconds {wall_clock}')
PY
fi

DRY_RUN=0
case "$#:${1:-}" in
  0:) ;;
  1:--dry-run) DRY_RUN=1 ;;
  *)
    echo "usage: docs/demo/record-$NAME.sh [--dry-run]" >&2
    exit 1
    ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
DOCKER_DIR="$REPO_ROOT/docs/demo/docker"
PATCH_FILE="vhs-0.12.0-render-context.patch"
# The container's limits (see the header). The sidecar records them as they ran, and --network none,
# which the render goes without, with its reason.
RUN_FLAGS=(--cap-drop ALL --security-opt no-new-privileges --pids-limit 256)

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d" " -f1; else shasum -a 256 | cut -d" " -f1; fi
}

# The pins of the render image as the Dockerfile writes them: the builder and the base image by the
# digest of their image index, and the repository, tag and commit of the VHS source. The sidecar
# records these strings, so a sidecar names the pins of the Dockerfile at the commit it ran from.
read_pins() {
  local by_digest='^[^@[:space:]]+@sha256:[0-9a-f]{64}$' by_commit='^[0-9a-f]{40}$' ref
  BUILDER_IMAGE="$(sed -n -E 's/^FROM ([^ ]+) AS vhsbuild$/\1/p' "$1")"
  BASE_IMAGE="$(sed -n -E 's/^FROM ([^ ]+)$/\1/p' "$1")"
  SOURCE_REPOSITORY="$(sed -n -E 's/^ARG VHS_REPOSITORY=(.+)$/\1/p' "$1")"
  SOURCE_TAG="$(sed -n -E 's/^ARG VHS_TAG=(.+)$/\1/p' "$1")"
  SOURCE_COMMIT="$(sed -n -E 's/^ARG VHS_COMMIT=(.+)$/\1/p' "$1")"
  for ref in "$BUILDER_IMAGE" "$BASE_IMAGE"; do
    if [ -z "$ref" ]; then
      echo "record-$NAME.sh: docs/demo/docker/Dockerfile has no FROM line for the build stage (AS vhsbuild) or for the render stage; not recording." >&2
      exit 1
    fi
    if ! [[ $ref =~ $by_digest ]]; then
      echo "record-$NAME.sh: docs/demo/docker/Dockerfile names $ref in a FROM line, not an image by the digest of its index. \`docker buildx imagetools inspect ${ref%%@*}\` prints that digest; write the line as FROM ${ref%%@*}@sha256:<digest> and run again." >&2
      exit 1
    fi
  done
  if ! [[ $SOURCE_COMMIT =~ $by_commit ]] || [ -z "$SOURCE_REPOSITORY" ] || [ -z "$SOURCE_TAG" ]; then
    echo "record-$NAME.sh: docs/demo/docker/Dockerfile does not name the VHS source by ARG VHS_REPOSITORY, VHS_TAG and VHS_COMMIT, a commit of 40 hex digits. \`git ls-remote --tags ${SOURCE_REPOSITORY:-<repository>} ${SOURCE_TAG:-<tag>}\` prints the tag's commit, on its ^{} line when the tag is annotated; write the three lines and run again." >&2
    exit 1
  fi
}

# The image is named after the recipe it is built from, so an edit to the Dockerfile or the patch
# builds a new image instead of reusing an old one.
IMAGE="atx-conformance-vhs:$(cat "$DOCKER_DIR/Dockerfile" "$DOCKER_DIR/$PATCH_FILE" | sha256_of | cut -c1-12)"
HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
HEAD_TAGS="$(git -C "$REPO_ROOT" tag --points-at HEAD | paste -s -d " " -)"

if [ "$DRY_RUN" = 1 ]; then
  read_pins "$DOCKER_DIR/Dockerfile"
  echo "record-$NAME.sh --dry-run: runs git and no docker command; no file is written."
  echo "  image     $IMAGE, built with $DOCKER from docs/demo/docker/Dockerfile"
  echo "  bases     $(sed -n -E 's/^FROM ([^ ]+).*/\1/p' "$DOCKER_DIR/Dockerfile" | paste -s -d " " -)"
  echo "  source    $SOURCE_REPOSITORY $SOURCE_TAG, commit $SOURCE_COMMIT"
  echo "  tape      $TAPE"
  echo "  runs      go run $MODULE/cmd/$NAME@latest, the version the Go module proxy names when it runs"
  echo "  container ${RUN_FLAGS[*]}, with the network; docs/demo mounted read-only, the render's files copied into it from a directory of its own"
  echo "  checkout  $HEAD_SHA${HEAD_TAGS:+, tags $HEAD_TAGS}"
  echo "  writes    $(sed -n -E 's/^(Output|Screenshot) (.*)$/\2/p' "$REPO_ROOT/$TAPE" | paste -s -d " " -) docs/demo/$NAME-capture.txt docs/demo/$NAME.json, and the version in docs/demo/$NAME.narration.json"
  echo "  docker    a configuration of the script's own, with no credential helper and no registry credentials"
  exit 0
fi

CONTEXT="$(mktemp -d)"
OWN_DOCKER_CONFIG="$(mktemp -d)"
RENDER_DIR="$(mktemp -d)"
KEEP_RENDER_DIR=0
cleanup() {
  rm -rf "$CONTEXT" "$OWN_DOCKER_CONFIG"
  if [ "$KEEP_RENDER_DIR" = 0 ]; then rm -rf "$RENDER_DIR"; fi
}
trap cleanup EXIT
cp "$DOCKER_DIR/Dockerfile" "$DOCKER_DIR/$PATCH_FILE" "$CONTEXT/"
read_pins "$CONTEXT/Dockerfile"

# The files a render writes into docs/demo, by their paths in the checkout: the tape's Output and
# Screenshot files, each of which must lie under docs/demo, and the capture.
WRITES=()
under_demo='^docs/demo/([A-Za-z0-9_-][A-Za-z0-9._-]*/)*[A-Za-z0-9_-][A-Za-z0-9._-]*$'
while IFS= read -r path; do
  if ! [[ $path =~ $under_demo ]]; then
    echo "record-$NAME.sh: $TAPE names $path as an output, which is not a file under docs/demo; not recording." >&2
    exit 1
  fi
  WRITES+=("$path")
done < <(sed -n -E 's/^(Output|Screenshot) (.*)$/\2/p' "$REPO_ROOT/$TAPE")
WRITES+=("docs/demo/$NAME-capture.txt")

# The docker configuration of this script's own (see the header). The endpoint and the plugin
# directories are read with the caller's configuration, before it is replaced.
PLUGIN_DIRS=""
for dir in "${DOCKER_CONFIG:-$HOME/.docker}/cli-plugins" /Applications/Docker.app/Contents/Resources/cli-plugins; do
  if [ -d "$dir" ]; then
    escaped="${dir//\\/\\\\}"
    PLUGIN_DIRS="${PLUGIN_DIRS:+$PLUGIN_DIRS, }\"${escaped//\"/\\\"}\""
  fi
done
if [ -z "${DOCKER_HOST:-}" ]; then
  DOCKER_HOST="$("$DOCKER" context inspect --format '{{.Endpoints.docker.Host}}')" || DOCKER_HOST=""
  if [ -z "$DOCKER_HOST" ]; then
    echo "record-$NAME.sh: $DOCKER context inspect named no endpoint for the docker context in use; set DOCKER_HOST and run again." >&2
    exit 1
  fi
fi
printf '{\n  "cliPluginsExtraDirs": [%s]\n}\n' "$PLUGIN_DIRS" > "$OWN_DOCKER_CONFIG/config.json"
export DOCKER_HOST
export DOCKER_CONFIG="$OWN_DOCKER_CONFIG"

"$DOCKER" build -t "$IMAGE" "$CONTEXT"
IMAGE_ID="$("$DOCKER" image inspect --format '{{.Id}}' "$IMAGE")"
# The base image's version and revision labels, which the image built on it carries unchanged.
BASE_VERSION="$("$DOCKER" image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$IMAGE")"
BASE_REVISION="$("$DOCKER" image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"

# A render that stops part way leaves no output and no sidecar from an earlier one in docs/demo.
rm -f "$REPO_ROOT/docs/demo/$NAME.json"
for path in "${WRITES[@]}"; do rm -f "$REPO_ROOT/$path"; done

STATUS=0
"$DOCKER" run --rm --pull never --hostname laptop --shm-size=1g "${RUN_FLAGS[@]}" \
  -e HOME=/work/demo-user \
  -e HEAD_TAGS="$HEAD_TAGS" \
  -e IMAGE="$IMAGE" \
  -e IMAGE_ID="$IMAGE_ID" \
  -e BASE_IMAGE="$BASE_IMAGE" \
  -e BASE_VERSION="$BASE_VERSION" \
  -e BASE_REVISION="$BASE_REVISION" \
  -e BUILDER_IMAGE="$BUILDER_IMAGE" \
  -e SOURCE_REPOSITORY="$SOURCE_REPOSITORY" \
  -e SOURCE_TAG="$SOURCE_TAG" \
  -e SOURCE_COMMIT="$SOURCE_COMMIT" \
  -e RUN_FLAGS="${RUN_FLAGS[*]}" \
  -v "$REPO_ROOT/docs/demo":/work/input/docs/demo:ro \
  -v "$RENDER_DIR":/work/docs/demo \
  --entrypoint bash "$IMAGE" "/work/input/docs/demo/record-$NAME.sh" --in-container || STATUS=$?

# The render's files reach docs/demo only after it wrote the sidecar, and only as regular files from
# a directory that holds no link, so a render places nothing there but its own files. The sidecar is
# copied last.
stop() {
  KEEP_RENDER_DIR=1
  echo "record-$NAME.sh: $2; nothing was copied into docs/demo, and what the render wrote is in $RENDER_DIR." >&2
  exit "$1"
}
[ "$STATUS" = 0 ] || stop "$STATUS" "the render exited $STATUS"
COPIES=("${WRITES[@]}")
if [ -e "$RENDER_DIR/$NAME.narration.json" ] || [ -L "$RENDER_DIR/$NAME.narration.json" ]; then
  COPIES+=("docs/demo/$NAME.narration.json")
fi
COPIES+=("docs/demo/$NAME.json")
[ -z "$(find "$RENDER_DIR" -type l | head -n 1)" ] || stop 1 "the render's directory holds a link"
for path in "${COPIES[@]}"; do
  [ -f "$RENDER_DIR/${path#docs/demo/}" ] || stop 1 "the render wrote no file $path"
done
for path in "${COPIES[@]}"; do
  mkdir -p "$(dirname "$REPO_ROOT/$path")"
  cp "$RENDER_DIR/${path#docs/demo/}" "$REPO_ROOT/$path"
done

# The line a release record or a task log keeps: which sidecar this render wrote, by its hash.
echo "sidecar: docs/demo/$NAME.json sha256 $(sha256_of < "$REPO_ROOT/docs/demo/$NAME.json")"
