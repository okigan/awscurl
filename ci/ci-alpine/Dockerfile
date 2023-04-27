FROM alpine

# RUN echo 'tzdata tzdata/Areas select Europe' | debconf-set-selections && \
#     echo 'tzdata tzdata/Zones/Europe select Paris' | debconf-set-selections && \
#     apk add --no-cache tzdata && \
#     cp /usr/share/zoneinfo/Europe/Paris /etc/localtime && \
#     echo "Europe/Paris" > /etc/timezone && \
#     apk del tzdata

RUN apk update && \
    apk add sudo curl git build-base autoconf automake libtool \
    openssl-dev readline-dev zlib-dev sqlite-dev ncurses-dev \
    xz-dev tk-dev libffi-dev bzip2-dev bash gcc make musl-dev \
    libffi-dev openssl-dev zlib-dev readline-dev sqlite-dev 

RUN curl https://pyenv.run | bash

ENV PATH="/root/.pyenv/bin:$PATH"

RUN eval "$(pyenv init -)" && \
    eval "$(pyenv virtualenv-init -)"


WORKDIR /root/workdir
COPY .python-version .python-version
RUN for version in $(cat .python-version); do \
    /root/.pyenv/bin/pyenv install $version; \
done

COPY setup.cfg setup.cfg
COPY awscurl awscurl
COPY setup.py setup.py
COPY scripts/ci.sh scripts/ci.sh
COPY requirements.txt requirements.txt
COPY requirements-test.txt requirements-test.txt
COPY tests tests

# RUN bash -c "source /root/venv/bin/activate && cd dd && tox --recreate"
