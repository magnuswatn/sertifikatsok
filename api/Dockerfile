#
# Python container for building
#
FROM python:3.8.2-slim-buster as build

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

COPY Pipfile /tmp/Pipfile
COPY Pipfile.lock /tmp/Pipfile.lock

RUN set -x \
    && cd /tmp \
    && /tmp/pipenv-venv/bin/pipenv install --deploy --system

COPY . /opt/sertifikatsok/api

#
# PROD container
#
FROM python:3.8.2-slim-buster

# Requirements for bonsai.
RUN set -x \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
        libldap2-dev libsasl2-dev

ENV PATH="/opt/sertifikatsok/venv/bin:${PATH}"

WORKDIR /opt/sertifikatsok/api

COPY --from=build /opt/sertifikatsok/venv/ /opt/sertifikatsok/venv/
COPY --from=build /opt/sertifikatsok/api/ /opt/sertifikatsok/api/

ENTRYPOINT ["python", "-um", "sertifikatsok"]
