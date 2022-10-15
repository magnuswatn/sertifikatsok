#!/bin/bash
set -Eeuo pipefail

temp_dir=$(mktemp --directory)

EXPECTED_CHEKSUM="f2c4402d6f65eb10afecd1729849ebac7ca8adf162060b2d24449af9f96c44b1  ${temp_dir}/materialize-v0.100.2.zip"

wget https://github.com/Dogfalo/materialize/releases/download/v0.100.2/materialize-v0.100.2.zip \
    -O "${temp_dir}/materialize-v0.100.2.zip"

echo "${EXPECTED_CHEKSUM}" | sha256sum -c

unzip "${temp_dir}/materialize-v0.100.2.zip"

rm -Rf "${temp_dir}"

mv "materialize" "materialize-v0.100.2"

wget https://code.jquery.com/jquery-3.2.1.min.js
wget https://fonts.gstatic.com/s/materialicons/v29/2fcrYFNaTjcS6g4U3t-Y5ZjZjT5FdEJ140U2DJYC3mY.woff2
