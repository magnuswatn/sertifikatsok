set positional-arguments

@clean-venv:
  pipenv --rm || true

@create-venv:
  pipenv sync --dev

@mkvenv: clean-venv create-venv update-lib

@run-dev:
  cd ./api && DEV=true pipenv run python -m sertifikatsok --host 127.0.0.1 --port 7001 2>&1

@run-testserver:
  cd ./testserver && pipenv run python -m testserver

@tests *args='':
  cd ./api && pipenv run pytest -m "not apitest" "$@"

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
  pipenv run maturin build --release -m ruldap3/Cargo.toml

@install-optimized-lib: build-lib
  pipenv run pip install --force-reinstall ./ruldap3/target/wheels/*

# docker compose stuff

@doctests *args='':
  docker compose -f docker-compose.yaml -f docker-compose.dev.yaml exec test pytest "$@"

@apitests:
  just doctests -m apitest

@docbuild:
  docker compose -f docker-compose.yaml -f docker-compose.dev.yaml build

@docps:
  docker compose -f docker-compose.yaml -f docker-compose.dev.yaml ps

@docdown:
  docker compose -f docker-compose.yaml -f docker-compose.dev.yaml down

@docup: docdown
  docker compose -f docker-compose.yaml -f docker-compose.dev.yaml up -d

# frontend stuff

@wwwdev:
  cd www && npm run dev || true

@wwwbuild:
  cd www && npm run build
