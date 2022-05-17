#!/bin/bash
SERTIFIKATSOK_DEBUG=true pipenv run uvicorn sertifikatsok.web:app
