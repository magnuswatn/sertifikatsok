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

  exit 0
done

exit 1
