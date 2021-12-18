#!/bin/bash
set -Eeuo pipefail

DIR="$( cd "$( dirname "$0" )" && pwd )"
BIN_DIR="$(readlink -f "$DIR/../../")"
CRL_DIR="$(readlink -f "$DIR/../api/crls")"

UGLIFY_ES=$BIN_DIR/node_modules/uglify-es/bin/uglifyjs
CSSO=$BIN_DIR/node_modules/csso-cli/bin/csso
HTML_MINFIER=$BIN_DIR/node_modules/html-minifier/cli.js
BROTLI=/usr/local/bin/brotli

CONTAINER_NAME="sertifikatsok-api"
CONTAINER_BACKUP_NAME="sertifikatsok-api-bak"

WWW_DIR=/var/www/sertifikatsok

cd "$DIR/../api"

head="$(git rev-parse HEAD)"
last_deploy="$(cat "${BIN_DIR}/last_deploy")"

if [[ $head == "$last_deploy" ]]; then
  # No changes since last deploy. Early exit.
  exit 0
fi

container_tag="sertifikatsok-api-$(date +%s)"

docker build \
  -t "${container_tag}" \
  "${DIR}/../api"

docker rm "${CONTAINER_BACKUP_NAME}" || true
docker stop "${CONTAINER_NAME}" || true
docker rename "${CONTAINER_NAME}" "${CONTAINER_BACKUP_NAME}" || true
docker run -d \
  --restart always \
  -v "${CRL_DIR}:/opt/sertifikatsok/api/crls" \
  -v "/var/log/caddy/:/logs" \
  -p 127.0.0.1:7001:7001 \
  --name "${CONTAINER_NAME}" \
  "${container_tag}" \
  --port 7001 --host 0.0.0.0 --log-files=/logs/sertifikatsok_{}.log

temp_dir=$(mktemp --directory)

cp "$DIR/../www/." "$temp_dir" -R
cd "$temp_dir"

# sertifikatsok.js and .css are subject to change, so best to add some cache busting
jshash=$(sha256sum ./resources/sertifikatsok.js | head -c 64)
mv ./resources/sertifikatsok.js "./resources/sertifikatsok-$jshash.js"
sed -i -e "s/sertifikatsok.js/sertifikatsok-$jshash.js/" index.html

csshash=$(sha256sum ./resources/sertifikatsok.css | head -c 64)
mv ./resources/sertifikatsok.css "./resources/sertifikatsok-$csshash.css"
sed -i -e "s/sertifikatsok.css/sertifikatsok-$csshash.css/" index.html

find "$temp_dir" -name '*.js' -type f -exec "$UGLIFY_ES"  '{}' --mangle safari10=true \
  --compress -o '{}' \;
find "$temp_dir" -name '*.css' -type f -exec "$CSSO" '{}' --output '{}' \;
find "$temp_dir" -name '*.html' -type f -exec "$HTML_MINFIER" --remove-comments \
  --collapse-whitespace --output '{}' '{}' \;

find "$temp_dir" -type f -not -name '*.png' -exec $BROTLI '{}' \;

rsync "$temp_dir/" $WWW_DIR --delete --recursive --checksum

rm -Rf "$temp_dir"

echo "$head" > "${BIN_DIR}/last_deploy"
