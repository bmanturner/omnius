FROM rust:1.97-bookworm AS build
WORKDIR /workspace
COPY . .
RUN cargo build --release --package {{project-name}}

FROM debian:bookworm-slim
COPY --from=build /workspace/target/release/{{project-name}} /usr/local/bin/service
USER 65532:65532
ENV OMNIUS_BIND=0.0.0.0:3000
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["service", "healthcheck"]
ENTRYPOINT ["service"]
CMD ["server"]
