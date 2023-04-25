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

COPY .python-version .python-version
RUN cat .python-version | xargs -n 1 /root/.pyenv/bin/pyenv install

RUN /root/.pyenv/versions/3.8*/bin/python -m venv /root/venv

RUN bash -c "source /root/venv/bin/activate && pip install tox"

COPY awscurl dd/awscurl
COPY tox.ini dd/tox.ini
COPY requirements.txt dd/requirements.txt
COPY requirements-test.txt dd/requirements-test.txt
COPY tests dd/tests

RUN bash -c "source /root/venv/bin/activate && cd dd && tox --recreate"
