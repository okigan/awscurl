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
