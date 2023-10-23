# Build stage
FROM python:3-alpine AS builder

RUN set -ex && \
  apk add \
  build-base \
  libffi-dev \
  libxml2-dev \
  openssl-dev

RUN pip install --user botocore

COPY . /app-source-dir

RUN pip install -v --user /app-source-dir 


# Runtime stage
FROM python:3-alpine

COPY --from=builder /root/.local /root/.local 

ENV PATH=/root/.local/bin/:${PATH}

ENTRYPOINT ["awscurl"]