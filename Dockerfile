#
# Node container for frontend build ("build")
#
FROM node:current-bookworm-slim@sha256:c88704924204ee6d4e9da02275a8fd27355502f7177e4175cd0d3a4375a9c9c8 as www-build

RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    brotli wget ca-certificates unzip

WORKDIR /tmp/extjsresources

COPY misc/download_external_resources.sh /tmp/download_external_resources.sh
RUN /tmp/download_external_resources.sh

COPY www /opt/sertifikatsok/www
WORKDIR /opt/sertifikatsok/www/

RUN ["cp", "--preserve=all", "-R", "/tmp/extjsresources/.", \
    "/opt/sertifikatsok/www/public/resources/external" ]

RUN npm install

ARG SERTIFIKATSOK_VERSION

RUN ["npm", "run", "build"]

RUN [ "find", "dist", "-type", "f", "-not", "-name", "*.woff2", \
    "-not", "-name", "*.woff", "-execdir", "brotli", "{}", ";" ]

#
# Python base container
#
FROM python:3.11.8-slim-bookworm@sha256:ce81dc539f0aedc9114cae640f8352fad83d37461c24a3615b01f081d0c0583a as python-base

#
# Build base container
#
FROM python-base as build-base

RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    gcc curl libc6-dev

#
# Python container for building the Rust lib
#
FROM build-base as rust-build

# Download and install rustup
RUN set -x && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    --default-toolchain stable --profile minimal

ENV PATH="/root/.cargo/bin/:${PATH}"

RUN set -x && python3 -m venv /opt/sertifikatsok/rust-venv
RUN set -x && /opt/sertifikatsok/rust-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip

COPY requirements/ruldap3.txt /tmp/ruldap-requirements.txt

RUN set -x \
    && /opt/sertifikatsok/rust-venv/bin/pip install --require-hashes -r /tmp/ruldap-requirements.txt

COPY ruldap3 /opt/sertifikatsok/ruldap3

RUN set -x \
    && /opt/sertifikatsok/rust-venv/bin/maturin build --release -m /opt/sertifikatsok/ruldap3/Cargo.toml --manylinux off


#
# Python container for building
#
FROM build-base as build

# Create venv for the app
RUN set -x && python3 -m venv /opt/sertifikatsok/venv
RUN set -x && /opt/sertifikatsok/venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip
ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}"

COPY requirements/main.txt /tmp/requirements.txt

RUN set -x \
    && cd /tmp \
    && /opt/sertifikatsok/venv/bin/pip install --require-hashes -r /tmp/requirements.txt

#
# Python container for testing
#
FROM build as test

COPY requirements/dev.txt /tmp/requirements.dev.txt

RUN set -x \
    && cd /tmp \
    && /opt/sertifikatsok/venv/bin/pip install --require-hashes -r /tmp/requirements.dev.txt

COPY --from=rust-build /opt/sertifikatsok/ruldap3/target/wheels /opt/sertifikatsok/ruldap3/target/wheels

RUN pip install /opt/sertifikatsok/ruldap3/target/wheels/*

#
# PROD container
#
FROM python-base

ARG SERTIFIKATSOK_VERSION

ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}" SERTIFIKATSOK_VERSION="${SERTIFIKATSOK_VERSION}"

WORKDIR /opt/sertifikatsok/api

COPY --from=www-build /opt/sertifikatsok/www/dist /opt/sertifikatsok/www/
COPY --from=build /opt/sertifikatsok/venv/ /opt/sertifikatsok/venv/
COPY --from=rust-build /opt/sertifikatsok/ruldap3/target/wheels /opt/sertifikatsok/ruldap3/target/wheels

RUN pip install /opt/sertifikatsok/ruldap3/target/wheels/*

COPY api /opt/sertifikatsok/api

ENTRYPOINT ["python", "-um", "sertifikatsok"]
