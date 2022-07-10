#
# Python container for building
#
FROM python:3.9-slim-bullseye as build

# Requirements for bonsai.
RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
        libldap2-dev libsasl2-dev

# Requirement for building bonsai. Separated to its own step
# so that the cache from the last step can be reused for the
# prod container.
RUN set -x \
    && apt-get install --no-install-recommends -y \
        gcc

# Create venv for pipenv
RUN set -x && python3 -m venv /tmp/pipenv-venv
RUN set -x \
    && /tmp/pipenv-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pip \
    && /tmp/pipenv-venv/bin/pip --no-cache-dir --disable-pip-version-check install --upgrade pipenv

# Create venv for the app
RUN set -x && python3 -m venv /opt/sertifikatsok/venv
RUN set -x && pip --no-cache-dir --disable-pip-version-check install --upgrade pip
ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}"

COPY ./api/Pipfile /tmp/Pipfile
COPY ./api/Pipfile.lock /tmp/Pipfile.lock

RUN set -x \
    && cd /tmp \
    && VIRTUAL_ENV=/opt/sertifikatsok/venv /tmp/pipenv-venv/bin/pipenv install --deploy

COPY ./api /opt/sertifikatsok/api

#
# Node container for frontend "building"
#
FROM node:lts-buster-slim as frontendbuild

# Requirements for building.
RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
        brotli

COPY ./www /opt/sertifikatsok/www

RUN find /opt/sertifikatsok/www -type f -not -name '*.png' -exec brotli '{}' \;

#
# PROD container
#
FROM python:3.9-slim-bullseye

# Requirements for bonsai.
RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
        libldap2-dev libsasl2-dev

ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}"

WORKDIR /opt/sertifikatsok/api

COPY --from=build /opt/sertifikatsok/venv/ /opt/sertifikatsok/venv/
COPY --from=build /opt/sertifikatsok/api/ /opt/sertifikatsok/api/
COPY --from=frontendbuild /opt/sertifikatsok/www /opt/sertifikatsok/www

ENTRYPOINT ["python", "-um", "uvicorn", "sertifikatsok.web:app", "--host", "0.0.0.0", "--port", "8080"]
