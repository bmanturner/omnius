ARG OMNIUS_WEB_BASE_PATH=/

FROM node:24.19.0-bookworm-slim AS web-build
ARG OMNIUS_WEB_BASE_PATH
ENV OMNIUS_WEB_BASE_PATH=$OMNIUS_WEB_BASE_PATH
WORKDIR /workspace
RUN npm install --global pnpm@11.23.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/web-sdk/package.json packages/web-sdk/package.json
COPY web/package.json web/package.json
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm --filter @omnius/web-sdk build
RUN pnpm --filter @omnius/web build

FROM rust:1.98-bookworm AS build
WORKDIR /workspace
COPY . .
RUN cargo build --release --locked --package reading-list

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ARG OMNIUS_WEB_BASE_PATH
ENV OMNIUS_WEB_BASE_PATH=$OMNIUS_WEB_BASE_PATH
COPY --from=build /workspace/target/release/reading-list /usr/local/bin/service
COPY --from=build /workspace/config /app/config
COPY --from=web-build /workspace/web/dist /app/web/dist
USER 65532:65532
ENV OMNIUS__SERVER__LISTEN_ADDRESS=0.0.0.0:3000
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["service", "healthcheck", "--address", "127.0.0.1:3000"]
ENTRYPOINT ["service"]
CMD ["server"]
