set positional-arguments

@clean-venv:
  rm -Rf .venv || true

@sync:
  uv sync --all-packages

@mkvenv: clean-venv sync

@run-dev:
  cd ./api && APP_DEV=true APP_RUN_BATCH=false uv run ../docker-entrypoint.sh --host 127.0.0.1 --port 7001 2>&1

@run-batch:
  cd ./api && APP_DEV=true uv run python3 -m sertifikatsok.brreg_batch 2>&1

@run-testserver:
  cd ./testserver && uv run python -m testserver

@tests *args='':
  cd ./api && uv run pytest -m "not apitest" "$@"

@ty:
  uv run ty check

@ruff:
  uv run ruff check && uv run ruff format --check

@checks: ruff ty tests

alias py := python
@python:
  uv run python

# docker compose stuff

@doctests *args='':
  docker compose -f docker-compose.yaml exec test pytest "$@"

@apitests:
  just doctests -m apitest

@docbuild:
  docker compose -f docker-compose.yaml build

@docps:
  docker compose -f docker-compose.yaml ps

@docdown:
  docker compose -f docker-compose.yaml down

@docup: docdown
  docker compose -f docker-compose.yaml up -d

# frontend stuff

@wwwdev-static:
  cd www && npm run dev || true

@wwwdev-api:
  cd www && VITE_PROXY=1 npm run dev || true

@wwwbuild:
  cd www && npm run build
