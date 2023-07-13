export LDFLAGS := "-L/opt/homebrew/opt/openldap/lib"

set positional-arguments

@clean-venv:
  pipenv --rm || true

@create-venv:
  pipenv sync --dev  --extra-pip-args '--no-binary 'bonsai''

@mkvenv: clean-venv create-venv update-lib

@run-dev:
  cd ./api && DEV=true pipenv run python -m sertifikatsok --host 127.0.0.1 --port 7001 2>&1

@run-testserver:
  cd ./testserver && pipenv run python -m testserver

@tests *args='':
  cd ./api && pipenv run pytest "$@"

@mypy:
  cd ./api && pipenv run mypy --version && pipenv run mypy .

@pre-commit:
  pre-commit run --all-files

@checks: pre-commit mypy tests

alias py := python
@python:
  pipenv run python

alias ulib := update-lib
@update-lib:
  pipenv run maturin develop -m ruldap3/Cargo.toml

@build-lib:
  pipenv run maturin build -m ruldap3/Cargo.toml

# docker-compose stuff

@docbuild:
  docker-compose build

@ps:
  docker-compose ps

@apitests:
  docker-compose exec test pytest 'tests/test_api.py'

@docup:
  docker-compose down && docker-compose up -d

# frontend stuff

@wwwdev:
  cd www && npm run dev || true

@wwwbuild:
  cd www && npm run build
