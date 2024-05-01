#
# Node container for frontend build ("build")
#
FROM node:current-bookworm-slim@sha256:2bf48899bbba183a33b362842c9a9832f19c99896159551f9a0420c53ec27522 as www-build

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
FROM python:3.11.9-slim-bookworm@sha256:3800945e7ed50341ba8af48f449515c0a4e845277d56008c15bd84d52093e958 as python-base

#
# Build base container
#
FROM python-base as build-base

RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
    gcc curl libc6-dev

# install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# (uv is installed to .cargo/bin)
ENV PATH="/root/.cargo/bin/:${PATH}"

#
# Python container for building the Rust lib
#
FROM build-base as rust-build

# Download and install rustup
RUN set -x && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    --default-toolchain stable --profile minimal

RUN set -x && uv venv --seed /opt/sertifikatsok/rust-venv
ENV VIRTUAL_ENV="/opt/sertifikatsok/rust-venv"

COPY requirements/ruldap3.txt /tmp/ruldap-requirements.txt

RUN set -x \
    && uv pip sync --require-hashes /tmp/ruldap-requirements.txt

COPY ruldap3 /opt/sertifikatsok/ruldap3

RUN set -x \
    && /opt/sertifikatsok/rust-venv/bin/maturin build --release -m /opt/sertifikatsok/ruldap3/Cargo.toml --manylinux off


#
# Python container for building
#
FROM build-base as build

# Create venv for the app
RUN set -x && uv venv --seed /opt/sertifikatsok/venv
ENV VIRTUAL_ENV="/opt/sertifikatsok/venv"
ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}"

COPY requirements/main.txt /tmp/requirements.txt

RUN set -x \
    && cd /tmp \
    && uv pip sync --require-hashes /tmp/requirements.txt

COPY --from=rust-build /opt/sertifikatsok/ruldap3/target/wheels /opt/sertifikatsok/ruldap3/target/wheels

RUN uv pip install /opt/sertifikatsok/ruldap3/target/wheels/*

#
# Python container for testing
#
FROM build as test

COPY requirements/dev.txt /tmp/requirements.dev.txt

RUN set -x \
    && cd /tmp \
    && uv pip sync --require-hashes /tmp/requirements.txt /tmp/requirements.dev.txt

# (ruldap3 was removed by the `uv pip sync` above, so we need to reinstall it)
COPY --from=rust-build /opt/sertifikatsok/ruldap3/target/wheels /opt/sertifikatsok/ruldap3/target/wheels

RUN uv pip install /opt/sertifikatsok/ruldap3/target/wheels/*

#
# PROD container
#
FROM python-base

ARG SERTIFIKATSOK_VERSION

ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}" SERTIFIKATSOK_VERSION="${SERTIFIKATSOK_VERSION}"

WORKDIR /opt/sertifikatsok/api

COPY --from=www-build /opt/sertifikatsok/www/dist /opt/sertifikatsok/www/
COPY --from=build /opt/sertifikatsok/venv/ /opt/sertifikatsok/venv/

COPY api /opt/sertifikatsok/api

ENTRYPOINT ["python", "-um", "sertifikatsok"]
