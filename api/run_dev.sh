#!/bin/bash
SERTIFIKATSOK_DEBUG=true pipenv run uvicorn --reload sertifikatsok.web:app
