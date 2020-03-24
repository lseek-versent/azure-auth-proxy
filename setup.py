#!/usr/bin/env python

from datetime import datetime
import setuptools


requirements = None
with open('requirements.txt', 'r') as requirement_file:
    all_contents = requirement_file.readlines()
    requirements = [line.strip() for line in all_contents if not line.startswith('#')]


setuptools.setup(name='authproxy',
      version='1.0+{}'.format(datetime.now().strftime('%y%m%d%H%M%S')),
      description='Proxy to automatically log into various services',
      author='David Koo',
      author_email='david.koo@versent.com.au',
      packages=setuptools.find_packages(),
      install_requires=requirements,
      entry_points={
          'console_scripts': [
              'authproxy=authproxy:main',
          ],
      },
      # Install interceptor script as an "executable" though it is not so that
      # it's in a convenient location
      scripts=['authproxy/samlInterceptor.py'])
