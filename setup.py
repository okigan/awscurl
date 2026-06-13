__author__ = 'iokulist'

from setuptools import setup  # type: ignore[import-untyped]

# https://github.com/okigan/awscurl/issues/167
# with open("requirements.txt", "r", encoding="utf-8") as f:
#     requirements = f.read().splitlines()

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

# https://blog.ganssle.io/articles/2021/10/setup-py-deprecated.html#summary

setup(
    name='awscurl',
    version='0.44',
    description='Curl like tool with AWS request signing',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='http://github.com/okigan/awscurl',
    author='Igor Okulist',
    author_email='okigan@gmail.com',
    license='MIT',
    packages=['awscurl'],
    # package_data={
    #     'tests': ['*.py'],
    # },
    entry_points={
        'console_scripts': [
            'awscurl = awscurl.__main__:main',
        ],
    },
    zip_safe=False,
    install_requires=[
        'requests',
        'configargparse',
        'configparser',
        'urllib3',
        "boto3",
        "botocore",
        "awscrt"
    ],
    extras_require={
        'awslibs': []
    }
)
