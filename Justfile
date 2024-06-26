set positional-arguments

@clean-venv:
  rm -Rf .venv || true

@create-venv:
  uv venv -p python3.11

@pip-sync:
  uv pip sync --require-hashes requirements/main.txt requirements/dev.txt requirements/ruldap3.txt

@sync: pip-sync update-lib

@mkvenv: clean-venv create-venv sync

@run-dev:
  source ./.venv/bin/activate && cd ./api && DEV=true python -m sertifikatsok --host 127.0.0.1 --port 7001 2>&1

@run-testserver:
  source ./.venv/bin/activate && cd ./testserver && python -m testserver

@tests *args='':
  source ./.venv/bin/activate && cd ./api && pytest -m "not apitest" "$@"

@mypy:
  source ./.venv/bin/activate && cd ./api && mypy --version && mypy .

@pre-commit:
  pre-commit run --all-files

@checks: pre-commit mypy tests

alias py := python
@python:
  source ./.venv/bin/activate && python

@compile:
  cd requirements && uv pip compile main.in -o main.txt --generate-hashes --no-header --no-strip-extras
  cd requirements && uv pip compile dev.in -o dev.txt --generate-hashes --no-header --no-strip-extras
  cd requirements && uv pip compile ruldap3.in -o ruldap3.txt --generate-hashes --no-header --no-strip-extras

@upgrade:
  cd requirements && uv pip compile main.in -o main.txt --generate-hashes --upgrade --no-header --no-strip-extras
  cd requirements && uv pip compile dev.in -o dev.txt --generate-hashes --upgrade --no-header --no-strip-extras
  cd requirements && uv pip compile ruldap3.in -o ruldap3.txt --generate-hashes --upgrade --no-header --no-strip-extras

@upgrade-pkg *args='':
  cd requirements && uv pip compile main.in -o main.txt --generate-hashes --no-header --upgrade-package --no-strip-extras "$@"
  cd requirements && uv pip compile dev.in -o dev.txt --generate-hashes --no-header --upgrade-package --no-strip-extras "$@"
  cd requirements && uv pip compile ruldap3.in -o ruldap3.txt --generate-hashes --no-header --upgrade-package --no-strip-extras "$@"

alias ulib := update-lib
@update-lib:
  source ./.venv/bin/activate && maturin develop -m ruldap3/Cargo.toml

@build-lib:
  source ./.venv/bin/activate && maturin build --release -m ruldap3/Cargo.toml

@install-optimized-lib: build-lib
  source ./.venv/bin/activate && pip install --force-reinstall ./ruldap3/target/wheels/*

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

@wwwdev-static:
  cd www && npm run dev || true

@wwwdev-api:
  cd www && VITE_PROXY=1 npm run dev || true

@wwwbuild:
  cd www && npm run build
