# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

# ───────────────────────────────────────────────
# Build environment in a docker container
# ───────────────────────────────────────────────
FROM debian:stable-slim AS builder

# Install build and test dependencies
RUN apt-get update && apt-get install -y \
    meson ninja-build build-essential \
    curl git unzip llvm llvm-dev strace \
    pkg-config python3 libssl-dev \
    wget ca-certificates perl cmake \
    libcmocka-dev meson ninja-build \
    gcc libc6-dev mc clang-format nano \
    && rm -rf /var/lib/apt/lists/*

# Instal rust and armerge with cargo
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install armerge

WORKDIR /src

# ───────────────────────────────────────────────
# Build OpenSSL 3.x from source
# ───────────────────────────────────────────────
ENV OPENSSL_VERSION=3.2.1

RUN wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar xzf openssl-${OPENSSL_VERSION}.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \
    ./Configure --prefix=/opt/openssl shared && \
    make -j"$(nproc)" && \
    make install_sw

ENV PATH="/opt/openssl/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/openssl/lib"

# ===================================================================
# 2. Build and install dependencies from source
# ===================================================================

# ───────────────────────────────────────────────
# 2.1 GTA API Core (main)
# ───────────────────────────────────────────────
RUN git clone --branch main https://github.com/generic-trust-anchor-api/gta-api-core.git gta-core
WORKDIR /src/gta-core

RUN meson setup builddir \
    && meson compile -C builddir \
    && meson install -C builddir

# ───────────────────────────────────────────────
# 2.2 GTA API Software Provider (main)
# ───────────────────────────────────────────────
WORKDIR /src
RUN git clone --branch main https://github.com/generic-trust-anchor-api/gta-api-sw-provider.git gta-sw-provider
WORKDIR /src/gta-sw-provider

RUN meson setup builddir \
    && meson compile -C builddir \
    && meson install -C builddir

RUN ls builddir

RUN armerge --keep-symbols 'gta_sw_provider_init' --output \
    builddir/libgta_sw_provider_merged.a \
    builddir/src/libgta_sw_provider.a \
    builddir/subprojects/openssl-3.0.8/libcrypto.a

# ───────────────────────────────────────────────
# 2.3 GTA CLI (main)
# ───────────────────────────────────────────────
WORKDIR /src
RUN git clone --branch main https://github.com/generic-trust-anchor-api/gta-cli.git gta-cli
WORKDIR /src/gta-cli

RUN meson setup builddir \
    && meson compile -C builddir \
    && meson install -C builddir

# ===================================================================
# 3. GTA OpenSSL provider (feature branch)
# ===================================================================
ARG MY_FEATURE_BRANCH="main"
ENV FEATURE_BRANCH=${MY_FEATURE_BRANCH}

WORKDIR /src
RUN git clone --branch "$FEATURE_BRANCH" \
    https://github.com/generic-trust-anchor-api/gta-api-for-openssl.git gta-openssl

# Copy normalized software provider to provider project
RUN cp -f /src/gta-sw-provider/builddir/libgta_sw_provider_merged.a /src/gta-openssl/deps/gta_api/lib_latest/libgta_sw_provider_merged.a

WORKDIR /src/gta-openssl

# Format/style check
# RUN clang-format --dry-run --Werror $(find . -name '*.c' -o -name '*.h\')

RUN meson setup builddir \
    && meson compile -C builddir \
    # && meson test -C builddir --print-errorlogs \
    && ninja -C builddir install

RUN ldconfig /src/gta-core/builddir
ENV LD_LIBRARY_PATH="/src/gta-core/builddir"

ENTRYPOINT ["/bin/bash"]

# Usage:

# Build (main):
# $ docker build -t gta-provider . 
# or
# $ docker buildx build -t gta-provider . --load

# Build (feature branch):
# $ docker build -t gta-provider --build-arg MY_FEATURE_BRANCH="5-chore-setup-meson-build-system" .
# or
# $ docker buildx build -t gta-provider --build-arg MY_FEATURE_BRANCH="5-chore-setup-meson-build-system" . --load

# Rebuild all: use --no-cache option

# Run:
# $ docker run -it gta-provider

# Test: 
# $ export MY_SERIALIZATION_FOLDER=.
# $ openssl list -provider gta

