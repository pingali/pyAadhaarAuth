#!/usr/bin/env python

from distutils.core import setup

setup(name='pyAadhaarAuth',
      version='0.1.0',
      description='UIDAI Authentication Python Client',
      author='Venkata Pingali',
      author_email='pingali@gmail.com',
      url='http://www.github.com/pingali/pyAadhaarAuth',
      packages=['AadhaarAuth'],
      license='LICENSE.txt',
      long_description=open('README.md').read(),
      requires=['lxml', 'config', 'M2Crypto', 'requests']
     )

