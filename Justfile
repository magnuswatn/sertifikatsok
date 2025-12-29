set positional-arguments

@clean-venv:
  rm -Rf .venv || true

@create-venv:
  uv venv -p python3.14

@pip-sync:
  uv pip sync --require-hashes requirements/main.txt requirements/dev.txt requirements/ruldap3.txt

@sync: pip-sync update-lib

@mkvenv: clean-venv create-venv sync

@run-dev:
  source ./.venv/bin/activate && cd ./api && DEV=true ../docker-entrypoint.sh --host 127.0.0.1 --port 7001 2>&1

@run-testserver:
  source ./.venv/bin/activate && cd ./testserver && python -m testserver

@tests *args='':
  source ./.venv/bin/activate && cd ./api && pytest -m "not apitest" "$@"

@mypy:
  source ./.venv/bin/activate && cd ./api && mypy --version && mypy .

@ruff:
  source ./.venv/bin/activate && ruff check && ruff format --check

@checks: ruff mypy tests

alias py := python
@python:
  source ./.venv/bin/activate && python

# Dependabot uses pip-tools, which thinks setuptools
# is a scary dependency, so it adds it to the requirement file
# after a warning. If Dependabot doesn't see the warning
# footer in the original requirements file, it will remove it,
# plus any dependency after it, from the finished file. So, to
# make sure Dependabot doesn't remove our setuptools dependency,
# we must add the header to the requirements file. And let's just
# move the setuptools dependency to it as well, to minimize diffs.
move_dev_setuptools_dependency_to_unsafe_footer:
  #!.venv/bin/python3
  from pathlib import Path

  dev_req = Path("requirements/dev.txt").read_text().splitlines()
  new_reqs = []
  setuptools_lines = []
  in_setuptools = False
  for line in dev_req:
      if line.startswith("setuptools=="):
          in_setuptools = True
          setuptools_lines.append(line)
      elif in_setuptools and line.startswith(" "):
          setuptools_lines.append(line)
      else:
          in_setuptools = False
          new_reqs.append(line)

  if setuptools_lines:
      new_reqs.extend(
          [
              "",
              "# The following packages are considered to be unsafe in a requirements file:",
              *setuptools_lines,
          ]
      )
  new_reqs.append("") # final newline
  Path("requirements/dev.txt").write_text("\n".join(new_reqs))


@compile:
  cd requirements && uv pip compile main.in -o main.txt --generate-hashes --no-header --no-strip-extras
  cd requirements && uv pip compile dev.in -o dev.txt --generate-hashes --no-header --no-strip-extras
  cd requirements && uv pip compile ruldap3.in -o ruldap3.txt --generate-hashes --no-header --no-strip-extras
  just move_dev_setuptools_dependency_to_unsafe_footer

@upgrade:
  cd requirements && uv pip compile main.in -o main.txt --generate-hashes --upgrade --no-header --no-strip-extras
  cd requirements && uv pip compile dev.in -o dev.txt --generate-hashes --upgrade --no-header --no-strip-extras
  cd requirements && uv pip compile ruldap3.in -o ruldap3.txt --generate-hashes --upgrade --no-header --no-strip-extras
  just move_dev_setuptools_dependency_to_unsafe_footer

@upgrade-pkg *args='':
  cd requirements && uv pip compile main.in -o main.txt --generate-hashes --no-header --no-strip-extras --upgrade-package "$@"
  cd requirements && uv pip compile dev.in -o dev.txt --generate-hashes --no-header --no-strip-extras --upgrade-package "$@"
  cd requirements && uv pip compile ruldap3.in -o ruldap3.txt --generate-hashes --no-header --no-strip-extras --upgrade-package "$@"
  just move_dev_setuptools_dependency_to_unsafe_footer

alias ulib := update-lib
@update-lib:
  source ./.venv/bin/activate && maturin develop --uv -m ruldap3/Cargo.toml

@build-lib:
  source ./.venv/bin/activate && maturin build --release -m ruldap3/Cargo.toml

@install-optimized-lib: build-lib
  source ./.venv/bin/activate && uv pip install --force-reinstall ./ruldap3/target/wheels/*

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
