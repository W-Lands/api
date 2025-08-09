#!/bin/bash

POETRY_VENV="$(poetry env info -p)"
export PATH="${PATH}:${POETRY_VENV}/bin"

export PYTHONUNBUFFERED=1
poetry run python -m wlands.migrate
poetry run gunicorn wlands.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8080 --preload