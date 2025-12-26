#!/bin/sh
exec uvicorn sertifikatsok.asgi:app "$@"
