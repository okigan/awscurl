FROM amazonlinux:2023

RUN yum update -y
RUN yum install -y sudo tar gzip make gcc openssl-devel bzip2-devel \
    libffi-devel zlib-devel readline-devel sqlite-devel xz-devel \
    git

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
