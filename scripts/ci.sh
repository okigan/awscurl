#!/bin/bash

DETOX_ROOT_DIR=./build/detox

grep -v '^ *#' < .python-version | while IFS= read -r PYENV_VERSION
do
    # echo PYENV_VERSION="$PYENV_VERSION"
    # echo SHELL="$SHELL"
    # echo $PATH
    # pyenv install -sv "${PYENV_VERSION}"
    # https://github.com/pyenv/pyenv/issues/1819#issuecomment-780803524
    # /root/.pyenv/bin/pyenv shell "${PYENV_VERSION}"
    export PYENV_VERSION="$PYENV_VERSION" 
    eval "$(pyenv init -)"

    PER_VER_DIR=${DETOX_ROOT_DIR}/v${PYENV_VERSION}
    VENV_DIR=${PER_VER_DIR}/venv${PYENV_VERSION}
    (
        echo "##### NEW DETOX ENV: " "$(uname) " "${PER_VER_DIR}" " #####"
        python3 -m venv "${VENV_DIR}"
        source "${VENV_DIR}"/bin/activate

        echo which python="$(which python)"
        echo python --version="$(python --version)"
        echo pip --version="$(pip --version)"
        
        PS4='[$(date "+%Y-%m-%d %H:%M:%S")] '
        set -o errexit -o pipefail -o nounset -o xtrace

        pip -q -q install --upgrade pip
        # python -m ensurepip --upgrade
        # pip install -r requirements.txt
        pip -q -q install -r requirements-test.txt

        pycodestyle .
        
        # python -m build . 
        pip -q install . 

        export AWS_ACCESS_KEY_ID=MOCK_AWS_ACCESS_KEY_ID
        export AWS_SECRET_ACCESS_KEY=MOCK_AWS_SECRET_ACCESS_KEY
        export AWS_SESSION_TOKEN=MOCK_AWS_SESSION_TOKEN

        pytest \
            --cov=awscurl \
            --cov-fail-under=77 \
            --cov-report html \
            --cov-report=html:"${PER_VER_DIR}"/htmlcov \
            --durations=2 \
            --strict-config
    )
done
