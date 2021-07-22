#!/bin/bash
set -Eeuo pipefail

SERVICE_USER=caddy
SERVICE_GROUP=caddy

if [[ $EUID -ne 0 ]]; then
  echo "Must be root."
  exit 1
fi

BIN_DIR="$(readlink -f ../../)"

chown $SERVICE_USER:$SERVICE_GROUP "$BIN_DIR" -R

cd "$BIN_DIR"
su $SERVICE_USER -c "npm install uglify-es"
su $SERVICE_USER -c "npm install csso-cli"
su $SERVICE_USER -c "npm install html-minifier"

su $SERVICE_USER -c -- "echo None > ${BIN_DIR}/last_deploy"

echo "Done."
