#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<EOF
Usage:
  ./scripts/check.sh <command>

Commands:
  test       Run pytest
  coverage   Run pytest and generate the local HTML coverage report
  mypy       Run mypy
  ty         Run ty
  ruff       Run ruff check
  ruff-fix   Run ruff check --fix
  format     Run ruff format
EOF
}

main() {
  if [[ "$#" -ne 1 ]]; then
    usage
    exit 1
  fi

  cd "$ROOT_DIR"

  case "$1" in
    test)
      uv run pytest
      ;;
    coverage)
      uv run pytest
      rm -rf reports/coverage/lcoview
      mkdir -p reports/coverage/lcoview
      docker build --tag zero-auth-lite-lcoview:1.1.1 tools/lcoview
      docker run --rm \
        --network none \
        --read-only \
        --tmpfs /tmp \
        --user "$(id -u):$(id -g)" \
        --volume "$ROOT_DIR:/workspace:ro" \
        --volume "$ROOT_DIR/reports/coverage/lcoview:/workspace/reports/coverage/lcoview" \
        --workdir /workspace \
        zero-auth-lite-lcoview:1.1.1 \
        reports/coverage/coverage.lcov \
        --source-dir . \
        --dest-dir reports/coverage/lcoview
      ;;
    mypy)
      uv run mypy --explicit-package-bases app
      ;;
    ty)
      uv run ty check app
      ;;
    ruff)
      uv run ruff check app tests docs/snippets scripts
      ;;
    ruff-fix)
      uv run ruff check app tests docs/snippets scripts --fix
      ;;
    format)
      uv run ruff format app tests docs/snippets scripts
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "Unknown command: $1" >&2
      echo >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
