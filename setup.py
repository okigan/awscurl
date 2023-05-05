__author__ = 'iokulist'

from setuptools import setup


with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

# https://blog.ganssle.io/articles/2021/10/setup-py-deprecated.html#summary

setup(
    name='awscurl',
    version='0.28',
    description='Curl like tool with AWS request signing',
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
    install_requires=requirements,
    extras_require={
        'awslibs': ["botocore"]
    }
)
