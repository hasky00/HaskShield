FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin haskshield

FROM debian:bookworm-slim
COPY --from=build /src/target/release/haskshield /usr/local/bin/haskshield
USER nobody
EXPOSE 7778
ENTRYPOINT ["haskshield"]
