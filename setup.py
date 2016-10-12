__author__ = 'iokulist'

from setuptools import setup

setup(
    name='awscurl',
    version='0.8',
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
        'urllib3[secure]'
    ]
)
