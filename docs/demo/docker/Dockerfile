# The render image of docs/demo/record-atx-verify.sh.
# VHS 0.12.0 with the encode-context regression patched (evaluator.go renders with the
# cancelled recording context, so ffmpeg never starts and the error is swallowed).
# The patch is the committed file next to this Dockerfile; its sha256 goes into the sidecar.
#
# Each input is pinned: both images by the digest of their image index (the manifest list, so the
# build resolves on arm64 and amd64 alike), the VHS source by commit. record-atx-verify.sh copies
# the two FROM references and the VHS_ arguments below into the sidecar's `recorder` as they are
# written here. To move a pin, `docker buildx imagetools inspect <image>:<tag>` prints the index
# digest and `git ls-remote --tags <repository> <tag>` the commit (on the `^{}` line of an
# annotated tag); write the new value with the version it resolves to beside it.

# golang:1.26-trixie on 2026-10-29: Go 1.26.10. Its /usr/local/go is also the render's Go toolchain.
FROM golang:1.26-trixie@sha256:a050dcceee6eb9bf110151662dfac7662f3bec40927c7dee48731e3d92083d42 AS vhsbuild
# GOTOOLCHAIN=local: a go.mod that asks for a newer Go fails the build instead of downloading a
# toolchain from outside the pin.
ENV GOTOOLCHAIN=local
# VHS_COMMIT is the commit the annotated tag VHS_TAG points to; the source is fetched by it.
ARG VHS_REPOSITORY=https://github.com/charmbracelet/vhs
ARG VHS_TAG=v0.12.0
ARG VHS_COMMIT=db96d7374f7d7a3774f69a43f4fcc5c5a1fd74e3
COPY vhs-0.12.0-render-context.patch /tmp/vhs-0.12.0-render-context.patch
RUN git init -q /src \
 && cd /src \
 && git fetch -q --depth 1 "$VHS_REPOSITORY" "$VHS_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && git apply /tmp/vhs-0.12.0-render-context.patch \
 && grep -n "v.Render(context.Background())" evaluator.go \
 && CGO_ENABLED=0 go build -ldflags "-X main.Version=$VHS_TAG+render-context-patch" -o /vhs .

# The base image carries ttyd, ffmpeg, Chromium, JetBrains Mono and python3. The Go toolchain
# of the first stage is copied in because the tape types the README's `go run` command, and
# gifsicle optimises the GIF.
# ghcr.io/charmbracelet/vhs:latest on 2026-10-29: VHS v0.12.1, revision
# 24fa2254a9806091e6ee6a980e9f3bcfe0a9ba53 (the image's org.opencontainers.image labels).
FROM ghcr.io/charmbracelet/vhs@sha256:ea49a6a1c529be83153e88321892b5585964418f0b9055e8c1e0d732194234a3
COPY --from=vhsbuild /vhs /usr/bin/vhs
COPY --from=vhsbuild /usr/local/go /usr/local/go
# apt-get upgrade installs the Debian updates published after the base image was built.
RUN apt-get update -qq && apt-get upgrade -y -qq >/dev/null \
 && apt-get install -y -qq --no-install-recommends ca-certificates gifsicle >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && which gifsicle python3 ffprobe
# GOTOOLCHAIN=local: `go run` uses the toolchain above and never downloads another one, so a
# toolchain download is never part of a recording. GOPROXY names the Go module proxy alone, with
# no `,direct`, so a module the proxy does not serve fails the command instead of being fetched
# from its origin; GOSUMDB names the checksum database the downloads are checked against.
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
WORKDIR /work
ENTRYPOINT ["vhs"]
