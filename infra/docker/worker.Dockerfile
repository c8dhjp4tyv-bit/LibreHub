FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG TARGETARCH
ARG FLATPAK_VERSION=1.16.6-1~deb13u3
ARG FLATPAK_BUILDER_VERSION=1.4.4-2
ARG BUBBLEWRAP_VERSION=0.12.0-1~deb13u1
ARG GIT_VERSION=1:2.47.3-0+deb13u1
ARG JQ_VERSION=1.7.1-6+deb13u4
ARG RUNTIME_BRANCH=25.08
ARG RUNTIME_COMMIT_AMD64=d27f7a6a974e40b061070bec1be9e1b52a7a6872b271e6a45c2c34a48bf6fedf
ARG SDK_COMMIT_AMD64=0cc82216a407cc993941b5ddabd446becc3c9a6219d9bcf50125c60101dcad46
ARG RUNTIME_COMMIT_ARM64=d56d30d8b124c41b689ae2adfb7cb01f7b1850d1d4741b83782607a074788339
ARG SDK_COMMIT_ARM64=a5fa55f615f74a6622167106f69c77d8a1483dd51d7b2beeb3e32667f00cec72
ENV HOME=/home/builder \
    XDG_DATA_HOME=/home/builder/.local/share \
    XDG_CACHE_HOME=/home/builder/.cache \
    XDG_RUNTIME_DIR=/work/run
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates "flatpak=$FLATPAK_VERSION" "flatpak-builder=$FLATPAK_BUILDER_VERSION" "bubblewrap=$BUBBLEWRAP_VERSION" dbus "jq=$JQ_VERSION" "git=$GIT_VERSION" curl \
    patch unzip xz-utils bzip2 gzip tar make gcc g++ pkg-config python3 \
    elfutils binutils rsync && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home builder \
    && mkdir -p /work /work/run && chown -R builder:builder /work \
    && chmod 700 /work/run
USER 10001:10001
# Seed runtimes in the immutable image. Build containers never get a host runtime mount.
RUN case "$TARGETARCH" in amd64) arch=x86_64; runtime_commit="$RUNTIME_COMMIT_AMD64"; sdk_commit="$SDK_COMMIT_AMD64" ;; arm64) arch=aarch64; runtime_commit="$RUNTIME_COMMIT_ARM64"; sdk_commit="$SDK_COMMIT_ARM64" ;; *) exit 1 ;; esac \
    && flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo \
    && flatpak install --user --noninteractive --no-related --arch="$arch" flathub \
       "org.freedesktop.Platform//$RUNTIME_BRANCH" "org.freedesktop.Sdk//$RUNTIME_BRANCH" \
    && flatpak update --user --noninteractive --no-related --arch="$arch" --commit="$runtime_commit" "org.freedesktop.Platform//$RUNTIME_BRANCH" \
    && flatpak update --user --noninteractive --no-related --arch="$arch" --commit="$sdk_commit" "org.freedesktop.Sdk//$RUNTIME_BRANCH" \
    && test "$(flatpak info --user --arch="$arch" --show-commit "org.freedesktop.Platform//$RUNTIME_BRANCH")" = "$runtime_commit" \
    && test "$(flatpak info --user --arch="$arch" --show-commit "org.freedesktop.Sdk//$RUNTIME_BRANCH")" = "$sdk_commit"
COPY --chmod=755 infra/docker/librehub-build /usr/local/bin/librehub-build
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/librehub-build"]
