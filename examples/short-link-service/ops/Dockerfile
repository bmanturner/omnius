FROM rust:1.98-bookworm AS build
WORKDIR /workspace
COPY . .
RUN cargo build --release --locked --package short-link-service

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /workspace/target/release/short-link-service /usr/local/bin/service
COPY --from=build /workspace/config /app/config
USER 65532:65532
ENV OMNIUS__SERVER__LISTEN_ADDRESS=0.0.0.0:3000
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["service", "healthcheck", "--address", "127.0.0.1:3000"]
ENTRYPOINT ["service"]
CMD ["server"]
