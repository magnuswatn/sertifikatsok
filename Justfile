export LDFLAGS := "-L/opt/homebrew/opt/openldap/lib"

set positional-arguments

@mkvenv:
  cd ./api && ( pipenv --rm || true ) && pipenv sync --dev --extra-pip-args '--no-binary 'bonsai''

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

# TODO: add frontend stuff also here
