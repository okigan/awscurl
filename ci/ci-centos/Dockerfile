FROM tgagor/centos

RUN yum update -y
RUN yum group install -y "Development Tools"
RUN yum install -y libffi-devel readline-devel zlib-devel bzip2-devel sqlite-devel openssl-devel git


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
