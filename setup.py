#!/usr/bin/env python

from distutils.core import setup

classifiers = [    
    'Development Status :: 2 - Pre-Alpha',    
    'Intended Audience :: Developers',    
    'License :: OSI Approved :: MIT License',
    'Operating System :: POSIX',    
    'Programming Language :: Python',    
    'Topic :: System :: Systems Administration :: Authentication/Directory']


setup(name='pyAadhaarAuth',
      version='0.1.0',
      description='UIDAI Authentication Python Client',
      author='Venkata Pingali',
      author_email='pingali@gmail.com',
      url='http://www.github.com/pingali/pyAadhaarAuth',
      packages=['AadhaarAuth', 'AadhaarAuth.lib'],
      scripts=['bin/aadhaar-sample-client.py', 
               'bin/aadhaar-batch-client.py',
               'bin/aadhaar-generate-client.py', 
               'bin/aadhaar-asa-client.py',
               'bin/aadhaar-asa-server.py'],
      package_data={'AadhaarAuth':['fixtures/*', 'xsd/*']},
      license='LICENSE.txt',
      long_description=open('README.md').read(),
      classifiers=classifiers, 
      requires=['lxml', 'config', 'M2Crypto', 'requests', 'config',
                'pyxmlsec' ]
     )

