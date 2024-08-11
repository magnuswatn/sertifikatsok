#!/bin/bash

trap 'exit 0' SIGTERM

x=0
while [[ x -le 15 ]]; do
  sleep 1

  if ! curl -s http://ldap_server_test/ping; then
    x=$(( x + 1 ))
    continue
  fi
  echo "Contact with server for test env"

  if ! curl -s http://ldap_server_prod/ping; then
    x=$(( x + 1 ))
    continue
  fi

  echo "Contact with server for prod env"

  # Delete CRL cache, since new CA databases have been
  # created
  rm /opt/sertifikatsok/api/crls/*.crl

  exit 0
done

exit 1
