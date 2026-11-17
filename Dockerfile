# Development container for leakgc (Fedora base).
# Build with `podman build -t leakgc-dev .` or `buildah bud -t leakgc-dev .`.
# Plain Dockerfile syntax only (no BuildKit-only features), so both work.

ARG FEDORA_VERSION=42
FROM quay.io/fedora/fedora:${FEDORA_VERSION}

ARG RUST_TOOLCHAIN=1.100.0
ARG CARGO_LLVM_COV_VERSION=0.9.1
ARG DEV_UID=1000

# pipefail so a failed curl in the rustup step fails the build.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# gcc: linker for Rust and build scripts. ocaml: reference oracle (ocaml/leakcheck.ml).
RUN dnf -y install gcc make git ocaml findutils tar xz curl-minimal \
 && dnf clean all

RUN useradd --create-home --uid "${DEV_UID}" dev

USER dev
WORKDIR /home/dev
ENV PATH="/home/dev/.cargo/bin:${PATH}"

# Rust is pinned to the toolchain the project was verified with, plus the
# components `cargo xtask lint` and `cargo xtask coverage` need.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_TOOLCHAIN}" \
      -c rustfmt -c clippy -c llvm-tools-preview

RUN cargo install cargo-llvm-cov --locked --version "${CARGO_LLVM_COV_VERSION}"

# The repository is bind-mounted here at run time; it is not copied into the image.
WORKDIR /workspace
CMD ["bash"]
