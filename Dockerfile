FROM python:2.7-alpine
COPY . /
RUN set -ex \
  && apk add --no-cache --virtual .build-deps \
    build-base \
    libffi-dev \
    libxml2-dev \
    openssl-dev \
  && apk add --no-cache --virtual .run-deps \
    libxslt-dev \
  && pip install -r requirements.txt \
  && apk del .build-deps

ENTRYPOINT ["python", "-m", "awscurl.awscurl"]

