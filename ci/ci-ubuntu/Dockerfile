FROM ubuntu

RUN apt update
RUN apt install -y sudo
RUN echo 'tzdata tzdata/Areas select Europe' | debconf-set-selections
RUN echo 'tzdata tzdata/Zones/Europe select Paris' | debconf-set-selections
RUN DEBIAN_FRONTEND="noninteractive" apt install -y tzdata

RUN apt install -y curl git \
    build-essential \
    autoconf \
    automake \
    libtool \
    libffi-dev libreadline-dev libz-dev libsqlite-dev libssl-dev \
    libreadline-dev libsqlite3-dev wget curl libncurses5-dev libncursesw5-dev \
    xz-utils tk-dev libffi-dev libbz2-dev liblzma-dev git

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
