#
# Node container for frontend build ("build")
#
FROM node:current-trixie-slim@sha256:191ef878ecb351d68b78219593de18bd8942afd59af59f29960dc4b24805a3f1 AS www-build

RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    brotli wget ca-certificates unzip

WORKDIR /tmp/extjsresources

COPY misc/download_external_resources.sh /tmp/download_external_resources.sh
RUN /tmp/download_external_resources.sh

COPY www /app/www
WORKDIR /app/www/

RUN ["cp", "--preserve=all", "-R", "/tmp/extjsresources/.", \
    "/app/www/public/resources/external" ]

RUN ["npm", "ci", "--ignore-scripts"]

ARG SERTIFIKATSOK_VERSION

RUN ["npm", "run", "build"]

RUN [ "find", "dist", "-type", "f", "-not", "-name", "*.woff2", \
    "-not", "-name", "*.woff", "-execdir", "brotli", "{}", ";" ]

#
# Python base container
#
FROM python:3.14.6-slim-trixie@sha256:44dd04494ee8f3b538294360e7c4b3acb87c8268e4d0a4828a6500b1eff50061 AS python-base

#
# Python container for building
#
FROM python-base AS build

RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    gcc curl libc6-dev

# Download and install rustup
RUN set -x && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    --default-toolchain stable --profile minimal

ENV PATH="/root/.cargo/bin/:${PATH}"

COPY --from=ghcr.io/astral-sh/uv:0.11.23@sha256:d0a0a753ab981624b49c97abc98821c1c09f4ca69d1ef5cee69c501be3d88479 /uv /usr/local/bin/uv

# - Silence uv complaining about not being able to use hard links,
# - tell uv to byte-compile packages for faster application startups,
# - prevent uv from accidentally downloading isolated Python builds,
# - pick a Python and finally declare `/app` as the target for `uv sync`.
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=python3.14 \
    UV_PROJECT_ENVIRONMENT=/app

WORKDIR /src

# build ruldap3
COPY ruldap3 /src/ruldap3

RUN --mount=type=cache,target=/root/.cache \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=api/pyproject.toml,target=api/pyproject.toml \
    --mount=type=bind,source=testserver/pyproject.toml,target=testserver/pyproject.toml \
    uv sync \
    --locked \
    --no-dev \
    --no-editable \
    --package ruldap3

# install external dependencies
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=api/pyproject.toml,target=api/pyproject.toml \
    --mount=type=bind,source=testserver/pyproject.toml,target=testserver/pyproject.toml \
    uv sync \
    --locked \
    --no-dev \
    --no-editable \
    --package sertifikatsok \
    --no-install-project

# install the main application
COPY api /src/api
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=testserver/pyproject.toml,target=testserver/pyproject.toml \
    uv sync \
    --locked \
    --no-dev \
    --no-editable \
    --package sertifikatsok

#
# Python container for testing
#
FROM build AS test

COPY testserver /src/testserver
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    uv sync \
    --locked \
    --no-editable \
    --package sertifikatsok \
    --package testserver

ENV PATH="/app/bin:${PATH}"

WORKDIR /app

#
# PROD container
#
FROM python-base

ARG SERTIFIKATSOK_VERSION

ENV PATH="/app/bin:${PATH}" SERTIFIKATSOK_VERSION="${SERTIFIKATSOK_VERSION}"

RUN <<EOT
groupadd -r app -g 1001
useradd -r -d /app/ -g app -N app -u 1001
EOT

WORKDIR /app

COPY docker-entrypoint.sh /
COPY --from=www-build --chown=app:app /app/www/dist /www/
COPY --from=build --chown=app:app /app /app
COPY --chown=app:app api/certs /app/certs

USER app

ENTRYPOINT ["/docker-entrypoint.sh"]
