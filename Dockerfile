#
# Node container for frontend build ("build")
#
FROM node:current-bookworm-slim@sha256:3a6fe61a331a31dd997016159374b8f398e8e7c5299b5f0ac7fd48c23e34ab5e as www-build

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
FROM python:3.11.4-slim-bookworm@sha256:364ee1a9e029fb7b60102ae56ff52153ccc929ceab9aa387402fe738432d24cc as python-base

# Requirements for bonsai.
RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    libldap2-dev libsasl2-dev

#
# Build base container
#
FROM python-base as build-base

RUN set -x \
    && apt-get install --no-install-recommends -y \
    gcc curl

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

COPY ruldap3/requirements.txt /tmp/ruldap-requirements.txt

RUN set -x \
    && /opt/sertifikatsok/rust-venv/bin/pip install --require-hashes -r /tmp/ruldap-requirements.txt

COPY ruldap3 /opt/sertifikatsok/ruldap3

RUN set -x \
    && /opt/sertifikatsok/rust-venv/bin/maturin build --release -m /opt/sertifikatsok/ruldap3/Cargo.toml --manylinux off


#
# Python container for building
#
FROM build-base as build

# Create venv for pipenv
RUN set -x && python3 -m venv /tmp/pipenv-venv
RUN set -x \
    && /tmp/pipenv-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip \
    && /tmp/pipenv-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pipenv

# Create venv for the app
RUN set -x && python3 -m venv /opt/sertifikatsok/venv
RUN set -x && /opt/sertifikatsok/venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip
ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}"

COPY Pipfile /tmp/Pipfile
COPY Pipfile.lock /tmp/Pipfile.lock

RUN set -x \
    && cd /tmp \
    && VIRTUAL_ENV=/opt/sertifikatsok/venv /tmp/pipenv-venv/bin/pipenv sync

#
# Python container for testing
#
FROM build as test

RUN set -x \
    && cd /tmp \
    && VIRTUAL_ENV=/opt/sertifikatsok/venv /tmp/pipenv-venv/bin/pipenv sync --dev

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
