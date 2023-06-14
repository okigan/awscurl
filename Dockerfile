# Build stage
FROM python:3-alpine AS builder

RUN set -ex && \
  apk add \
  build-base \
  libffi-dev \
  libxml2-dev \
  openssl-dev

COPY . /app-source-dir

RUN pip install --target=/app/python-packages ./app-source-dir 


# Runtime stage
FROM python:3-alpine

COPY --from=builder /app /app

ENV PATH=/app/python-packages/bin:${PATH}
ENV PYTHONPATH=/app/python-packages

ENTRYPOINT ["awscurl"]
