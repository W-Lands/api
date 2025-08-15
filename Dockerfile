FROM python:3.11-alpine

ENV POETRY_HOME=/opt/poetry
ENV POETRY_CACHE_DIR=/opt/.cache
ENV PATH="${PATH}:${POETRY_HOME}/bin"

WORKDIR "/wlands"

COPY poetry.lock poetry.lock
COPY pyproject.toml pyproject.toml

RUN apk update && apk add --no-cache libmagic git bash curl && apk add --no-cache --virtual build-deps gcc libc-dev && \
    python -m venv $POETRY_HOME && $POETRY_HOME/bin/pip install -U pip setuptools && $POETRY_HOME/bin/pip install poetry && \
    poetry install --only main --no-interaction --no-root && poetry add gunicorn && \
    apk del build-deps && \
    rm -rf /root/.cache $POETRY_CACHE_DIR/cache $POETRY_CACHE_DIR/artifacts

RUN wget -O /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.5/dumb-init_1.2.5_x86_64
RUN chmod +x /usr/local/bin/dumb-init

COPY . .
RUN chmod +x entrypoint.sh
RUN chmod +x entrypoint-internal.sh

ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]
CMD ["/wlands/entrypoint.sh"]
