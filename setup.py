from setuptools import setup
import codecs

__author__ = 'iokulist'


def long_description():
    with codecs.open('README.rst', encoding='utf8') as f:
        return f.read()

setup(name='awscurl',
      version='0.6',
      description='Curl like tool with AWS request signing',
      long_description=long_description(),
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
      requires=['requests', 'configargparse']
      )

