#!/bin/bash

DEV=true pipenv run python -m sertifikatsok --host 127.0.0.1 --port 7001 2>&1
