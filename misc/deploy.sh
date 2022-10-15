#!/bin/bash
set -Eeuo pipefail

DIR="$( cd "$( dirname "$0" )" && pwd )"
BIN_DIR="$(readlink -f "$DIR/../../")"
CRL_DIR="$(readlink -f "$DIR/../api/crls")"
DB_DIR="$(readlink -f "$DIR/../api/database")"

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

container_tag="sertifikatsok-api-${head}"

temp_dir=$(mktemp --directory)

docker build \
  -t "${container_tag}" \
  "${DIR}/.."

docker rm "${CONTAINER_BACKUP_NAME}" || true
docker stop "${CONTAINER_NAME}" || true
docker rename "${CONTAINER_NAME}" "${CONTAINER_BACKUP_NAME}" || true
docker run -d \
  --restart always \
  -v "${CRL_DIR}:/opt/sertifikatsok/api/crls" \
  -v "${DB_DIR}:/opt/sertifikatsok/api/database" \
  -v "${temp_dir}:/tmp/wwwcopy" \
  -v "/var/log/caddy/:/logs" \
  -p 127.0.0.1:7001:7001 \
  --name "${CONTAINER_NAME}" \
  "${container_tag}" \
  --port 7001 --host 0.0.0.0 --log-files=/logs/sertifikatsok_{}.log

docker exec "${CONTAINER_NAME}" cp --preserve=all -R /opt/sertifikatsok/www/. /tmp/wwwcopy

rsync "$temp_dir/" "${WWW_DIR}" --delete --recursive --checksum

echo "$head" > "${BIN_DIR}/last_deploy"
