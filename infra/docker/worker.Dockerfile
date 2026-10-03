FROM debian:trixie-slim
ARG TARGETARCH
ARG RUNTIME_BRANCH=25.08
ENV HOME=/home/builder \
    XDG_DATA_HOME=/home/builder/.local/share \
    XDG_CACHE_HOME=/home/builder/.cache \
    XDG_RUNTIME_DIR=/work/run
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates flatpak flatpak-builder bubblewrap dbus jq git curl \
    patch unzip xz-utils bzip2 gzip tar make gcc g++ pkg-config python3 \
    elfutils binutils rsync && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home builder \
    && mkdir -p /work /work/run && chown -R builder:builder /work \
    && chmod 700 /work/run
USER 10001:10001
# Seed runtimes in the immutable image. Build containers never get a host runtime mount.
RUN case "$TARGETARCH" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; *) exit 1 ;; esac \
    && flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo \
    && flatpak install --user --noninteractive --arch="$arch" flathub \
       "org.freedesktop.Platform//$RUNTIME_BRANCH" "org.freedesktop.Sdk//$RUNTIME_BRANCH"
COPY --chmod=755 infra/docker/librehub-build /usr/local/bin/librehub-build
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/librehub-build"]
