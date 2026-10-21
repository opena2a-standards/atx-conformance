# The render image of docs/demo/record-atx-verify.sh.
# VHS 0.12.0 with the encode-context regression patched (evaluator.go renders with the
# cancelled recording context, so ffmpeg never starts and the error is swallowed).
# The patch is the committed file next to this Dockerfile; its sha256 goes into the sidecar.
FROM golang:1.26-trixie AS vhsbuild
ENV GOTOOLCHAIN=auto
COPY vhs-0.12.0-render-context.patch /tmp/vhs-0.12.0-render-context.patch
RUN git clone --depth 1 --branch v0.12.0 https://github.com/charmbracelet/vhs /src \
 && cd /src \
 && git apply /tmp/vhs-0.12.0-render-context.patch \
 && grep -n "v.Render(context.Background())" evaluator.go \
 && CGO_ENABLED=0 go build -ldflags "-X main.Version=v0.12.0+render-context-patch" -o /vhs .

# The base image carries ttyd, ffmpeg, Chromium, JetBrains Mono and python3. The Go toolchain
# of the first stage is copied in because the tape types the README's `go run` command, and
# gifsicle optimises the GIF.
FROM ghcr.io/charmbracelet/vhs:latest
COPY --from=vhsbuild /vhs /usr/bin/vhs
COPY --from=vhsbuild /usr/local/go /usr/local/go
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates gifsicle >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && which gifsicle python3 ffprobe
# GOTOOLCHAIN=local: `go run` uses the toolchain above and never downloads another one, so a
# toolchain download is never part of a recording.
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local
WORKDIR /work
ENTRYPOINT ["vhs"]
