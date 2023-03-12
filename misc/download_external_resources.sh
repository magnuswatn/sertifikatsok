#!/bin/bash
set -Eeuo pipefail

MATERIALIZE_VERSION="1.2.1"
MATERIALIZE_FILENAME="materialize-v${MATERIALIZE_VERSION}"

temp_dir=$(mktemp -d)

EXPECTED_CHEKSUM="8df8ef1f247b4ba2e89edb32fc9c8d69d4d812d3707c3cbfe1ecf3c45fffa5e4  ${temp_dir}/${MATERIALIZE_FILENAME}.zip"

wget "https://github.com/materializecss/materialize/releases/download/${MATERIALIZE_VERSION}/${MATERIALIZE_FILENAME}.zip" \
    -O "${temp_dir}/${MATERIALIZE_FILENAME}.zip"

echo "${EXPECTED_CHEKSUM}" | sha256sum -c

unzip "${temp_dir}/${MATERIALIZE_FILENAME}.zip"

rm -Rf "${temp_dir}"

mv "materialize" "${MATERIALIZE_FILENAME}"

wget https://fonts.gstatic.com/s/materialicons/v139/flUhRq6tzZclQEJ-Vdg-IuiaDsNZ.ttf
