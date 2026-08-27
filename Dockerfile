# syntax=docker/dockerfile:1.7.0

FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS web-dependencies
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
WORKDIR /workspace
RUN corepack enable \
    && corepack prepare pnpm@11.23.0 --activate \
    && pnpm config set store-dir /pnpm/store
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY compat/web-w0/package.json compat/web-w0/package.json
COPY packages/web-sdk/package.json packages/web-sdk/package.json
COPY web/package.json web/package.json
RUN --mount=type=cache,id=omnius-pnpm-store,target=/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile

FROM web-dependencies AS web-build
ARG OMNIUS_GIT_REVISION
ARG OMNIUS_BUILD_TIME
ARG OMNIUS_SOURCE_MAP_POLICY=disabled
ARG OMNIUS_WEB_BASE_PATH=/
COPY contracts ./contracts
COPY crates/http/web-route-topology.json crates/http/web-route-topology.json
COPY packages/web-sdk ./packages/web-sdk
COPY web ./web
RUN test -n "$OMNIUS_GIT_REVISION" \
    && test -n "$OMNIUS_BUILD_TIME" \
    && pnpm sdk:check:generated \
    && pnpm sdk:build \
    && OMNIUS_GIT_REVISION="$OMNIUS_GIT_REVISION" \
       OMNIUS_BUILD_TIME="$OMNIUS_BUILD_TIME" \
       OMNIUS_SOURCE_MAP_POLICY="$OMNIUS_SOURCE_MAP_POLICY" \
       OMNIUS_WEB_BASE_PATH="$OMNIUS_WEB_BASE_PATH" \
       pnpm web:build

# This clean export target retains private maps only as part of the intended web artifact output.
FROM scratch AS web-private-artifacts
COPY --from=web-build /workspace/web/dist /web/dist

# Runtime artifacts remove disabled/private maps; only an explicit public build copies them.
FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS web-runtime-artifacts
WORKDIR /artifact
COPY --from=web-build /workspace/web/dist ./web/dist
ARG OMNIUS_SOURCE_MAP_POLICY=disabled
RUN case "$OMNIUS_SOURCE_MAP_POLICY" in \
      disabled|private) find web/dist -type f \( -name '*.map' -o -name '*.map.gz' -o -name '*.map.br' -o -name '*.map.zst' \) -delete ;; \
      public) ;; \
      *) echo 'OMNIUS_SOURCE_MAP_POLICY must be disabled, private, or public' >&2; exit 64 ;; \
    esac

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-build
WORKDIR /workspace
ARG OMNIUS_GIT_REVISION
ARG OMNIUS_BUILD_TIME
ENV CARGO_INCREMENTAL=0
COPY . .
RUN --mount=type=cache,id=omnius-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=omnius-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    test -n "$OMNIUS_GIT_REVISION" \
    && test -n "$OMNIUS_BUILD_TIME" \
    && OMNIUS_GIT_REVISION="$OMNIUS_GIT_REVISION" \
       OMNIUS_BUILD_TIME="$OMNIUS_BUILD_TIME" \
       cargo build --locked --release --package omnius-api-server

FROM debian:12.13-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3 AS runtime
ARG OMNIUS_GIT_REVISION
ARG OMNIUS_BUILD_TIME
ARG OMNIUS_SOURCE_MAP_POLICY=disabled
ARG OMNIUS_WEB_BASE_PATH=/
LABEL org.opencontainers.image.revision=$OMNIUS_GIT_REVISION \
      org.opencontainers.image.created=$OMNIUS_BUILD_TIME
WORKDIR /opt/omnius
COPY --from=rust-build --chown=65532:65532 /workspace/target/release/omnius-api-server /usr/local/bin/omnius-api-server
COPY --chown=65532:65532 config/reference.toml /etc/omnius/reference.toml
COPY --from=web-runtime-artifacts --chown=65532:65532 /artifact/web/dist ./web/dist
ENV OMNIUS__STATIC_DELIVERY__SOURCE_MAPS=$OMNIUS_SOURCE_MAP_POLICY \
    OMNIUS__STATIC_DELIVERY__BASE_PATH=$OMNIUS_WEB_BASE_PATH \
    OMNIUS__SERVER__LISTEN_ADDRESS=0.0.0.0:8080 \
    OMNIUS__TELEMETRY__ENVIRONMENT=production
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/omnius-api-server"]
CMD ["server", "--environment", "production", "--config", "/etc/omnius/reference.toml"]
