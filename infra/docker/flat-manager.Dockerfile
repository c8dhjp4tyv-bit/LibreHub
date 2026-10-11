FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build
ARG FLAT_MANAGER_REF=8da2bdda932ab0bf284af7eacbd803f548237222
RUN apt-get update && apt-get install -y --no-install-recommends git libpq-dev libostree-dev pkg-config libssl-dev libgpgme-dev cmake && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/flatpak/flat-manager.git /src && git -C /src checkout "$FLAT_MANAGER_REF"
WORKDIR /src
RUN cargo build --release --locked --bin flat-manager --bin flat-manager-client

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update && apt-get install -y --no-install-recommends flatpak ostree gnupg libpq5 ca-certificates python3 && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/gpg /usr/bin/gpg2
COPY --from=build /src/target/release/flat-manager /src/target/release/flat-manager-client /usr/local/bin/
COPY infra/docker/bootstrap-repository.py /usr/local/lib/librehub/bootstrap-repository.py
ENV REPO_CONFIG=/state/config.json
CMD ["flat-manager"]
