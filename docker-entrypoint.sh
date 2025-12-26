#!/bin/sh
exec granian sertifikatsok.asgi:app --interface ASGI --access-log "$@"
