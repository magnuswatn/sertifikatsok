export LDFLAGS := "-L/opt/homebrew/opt/openldap/lib"

set positional-arguments

@clean-venv:
  cd ./api && ( pipenv --rm || true )

@create-venv:
  cd ./api && pipenv sync --dev  --extra-pip-args '--no-binary 'bonsai''

@mkvenv: clean-venv create-venv update-lib

@run-dev:
  cd ./api && DEV=true pipenv run python -m sertifikatsok --host 127.0.0.1 --port 7001 2>&1

@tests *args='':
  cd ./api && pipenv run pytest "$@"

@mypy:
  cd ./api && pipenv run mypy --version && pipenv run mypy .

@pre-commit:
  pre-commit run --all-files

@checks: pre-commit mypy tests

alias py := python
@python:
  cd ./api && pipenv run python

alias ulib := update-lib
@update-lib:
  cd api && pipenv run maturin develop -m ../ruldap3/Cargo.toml

@build-lib:
  cd api && pipenv run maturin build -m ../ruldap3/Cargo.toml

# TODO: add frontend stuff also here
