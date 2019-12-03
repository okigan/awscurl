__author__ = 'iokulist'

from setuptools import setup

setup(
    name='awscurl',
    version='0.18',
    description='Curl like tool with AWS request signing',
    url='http://github.com/okigan/awscurl',
    author='Igor Okulist',
    author_email='okigan@gmail.com',
    license='MIT',
    packages=['awscurl'],
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
        'urllib3[secure]<1.24,>=1.21.1'
    ],
    extras_require={
        'awslibs': ["botocore"]
    }
)
