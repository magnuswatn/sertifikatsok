#!/bin/bash
set -Eeuo pipefail

SERVICE_USER=caddy
SERVICE_GROUP=caddy

# On RHEL with Python3.6 installed from EPEL it is currently
# only known as python36, not python3
export PYTHON=$(type -P python36 || type -P python3)
if [[ -z $PYTHON ]]; then
  echo "python3(6) was not found. Exiting"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Must be root."
  exit 1
fi

APP_DIR="$(readlink -f ../api)"
BIN_DIR="$(readlink -f ../../)"

cp sudoersfile 99-sertifikatsok
sed -i -e "s/SERVICE_USER/$SERVICE_GROUP/" 99-sertifikatsok
visudo -cf 99-sertifikatsok
mv 99-sertifikatsok /etc/sudoers.d

cp systemdfile sertifikatsok.service
ESCAPED_APP_PATH=${APP_DIR////\\/}
ESCAPED_BIN_PATH=${BIN_DIR////\\/}
sed -i -e "s/APPHOME/$ESCAPED_APP_PATH/" sertifikatsok.service
sed -i -e "s/BINHOME/$ESCAPED_BIN_PATH/" sertifikatsok.service
sed -i -e "s/SERVICE_USER/$SERVICE_USER/" sertifikatsok.service
sed -i -e "s/SERVICE_GROUP/$SERVICE_GROUP/" sertifikatsok.service

mv sertifikatsok.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sertifikatsok

chown $SERVICE_USER:$SERVICE_GROUP $BIN_DIR -R

cd $BIN_DIR
su $SERVICE_USER -c "$PYTHON -m venv pipenv-venv"
su $SERVICE_USER -c "pipenv-venv/bin/pip install --upgrade pip"
su $SERVICE_USER -c "pipenv-venv/bin/pip install pipenv"

su $SERVICE_USER -c "npm install uglify-es"
su $SERVICE_USER -c "npm install csso-cli"
su $SERVICE_USER -c "npm install html-minifier"

echo "Done."
