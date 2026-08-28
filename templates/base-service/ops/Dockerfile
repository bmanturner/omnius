{% if web_static or profile == "web" or profile == "realtime-web" or profile == "saas-web" or profile == "full-reference-web" -%}
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
RUN pnpm --filter @omnius/web build

{% endif -%}
FROM rust:1.98-bookworm AS build
WORKDIR /workspace
COPY . .
RUN cargo build --release --package {{project-name}}

FROM debian:bookworm-slim
{% if web_static or profile == "web" or profile == "realtime-web" or profile == "saas-web" or profile == "full-reference-web" -%}
ARG OMNIUS_WEB_BASE_PATH
ENV OMNIUS_WEB_BASE_PATH=$OMNIUS_WEB_BASE_PATH
WORKDIR /app
{% endif -%}
COPY --from=build /workspace/target/release/{{project-name}} /usr/local/bin/service
{% if web_static or profile == "web" or profile == "realtime-web" or profile == "saas-web" or profile == "full-reference-web" -%}
COPY --from=web-build /workspace/web/dist /app/web/dist
{% endif -%}
USER 65532:65532
ENV OMNIUS_BIND=0.0.0.0:3000
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["service", "healthcheck"]
ENTRYPOINT ["service"]
CMD ["server"]
