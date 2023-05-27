FROM tgagor/centos

RUN yum update -y
RUN yum group install -y "Development Tools"
RUN yum install -y libffi-devel readline-devel zlib-devel bzip2-devel sqlite-devel openssl-devel git


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
