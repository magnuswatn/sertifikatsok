#
# Node container for frontend build ("build")
#
FROM node:current-bullseye-slim as www-build

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
# Python container for building
#
FROM python:3.11.4-slim-bullseye@sha256:e2d50d4ac4d8a0cd6b44f07496ed14cf29f8c0000d12a22b4df8fff2c2432d0d as build

# Requirements for bonsai.
RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    libldap2-dev libsasl2-dev

# Requirement for building bonsai + downloading rustup. Separated to its own step
# so that the cache from the last step can be reused for the
# prod container.
RUN set -x \
    && apt-get install --no-install-recommends -y \
    gcc curl

# Download and install rustup
RUN set -x && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    --default-toolchain stable --profile minimal

ENV PATH="/root/.cargo/bin/:${PATH}"

# Create venv for pipenv
RUN set -x && python3 -m venv /tmp/pipenv-venv
RUN set -x \
    && /tmp/pipenv-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip \
    && /tmp/pipenv-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pipenv

# Create venv for building the rust lib
RUN set -x && python3 -m venv /opt/sertifikatsok/rust-venv
RUN set -x && /opt/sertifikatsok/rust-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip

# Create venv for the app
RUN set -x && python3 -m venv /opt/sertifikatsok/venv
RUN set -x && /opt/sertifikatsok/venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip
ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}"

COPY api/Pipfile /tmp/Pipfile
COPY api/Pipfile.lock /tmp/Pipfile.lock

RUN set -x \
    && cd /tmp \
    && VIRTUAL_ENV=/opt/sertifikatsok/venv /tmp/pipenv-venv/bin/pipenv sync

RUN set -x \
    && cd /tmp \
    && VIRTUAL_ENV=/opt/sertifikatsok/rust-venv /tmp/pipenv-venv/bin/pipenv sync --categories="rust"

COPY ruldap3 /opt/sertifikatsok/ruldap3

RUN set -x \
    && /opt/sertifikatsok/rust-venv/bin/maturin build -m /opt/sertifikatsok/ruldap3/Cargo.toml --manylinux off

RUN /opt/sertifikatsok/venv/bin/pip install /opt/sertifikatsok/ruldap3/target/wheels/*

COPY api /opt/sertifikatsok/api

#
# PROD container
#
FROM python:3.11.4-slim-bullseye@sha256:e2d50d4ac4d8a0cd6b44f07496ed14cf29f8c0000d12a22b4df8fff2c2432d0d

# Requirements for bonsai.
RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    libldap2-dev libsasl2-dev

ARG SERTIFIKATSOK_VERSION

ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}" SERTIFIKATSOK_VERSION="${SERTIFIKATSOK_VERSION}"

WORKDIR /opt/sertifikatsok/api

COPY --from=www-build /opt/sertifikatsok/www/dist /opt/sertifikatsok/www/
COPY --from=build /opt/sertifikatsok/venv/ /opt/sertifikatsok/venv/
COPY --from=build /opt/sertifikatsok/api/ /opt/sertifikatsok/api/

ENTRYPOINT ["python", "-um", "sertifikatsok"]
