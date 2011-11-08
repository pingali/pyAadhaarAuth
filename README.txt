===========================================================
Python Client and Library for Aadhaar Authentication Service
===========================================================

*THIS IS STILL UNDER DEVELOPMENT. DO NOT USE IT YET" 

This package supports biometrics and demographics authentication
using the Aadhaar Authentication Service (also known as UID).

FEATURES
========

1. Simple api 
2. Automatic UID numbering scheme, XSD validation, encryption,
   and other checks
3. Batch and timing information processing 
4. Extensive debugging information 
5. Easy configuration file 

EXAMPLE
=======

Please obtain and read the relevant certificates from UIDAI 
(https://developer.uidai.gov.in)

#!/usr/bin/env python
"""
Simplest possible python client
"""
import logging
import sys 
from config import Config 

from request import AuthRequest

if __name__ == '__main__':
    assert(sys.argv)
    if len(sys.argv) < 3:
        print "Usage: simple-client.py <config-file> <uid> <name>"
	print "Please use default config file in fixtures/auth.cfg" 
        sys.exit(1)  

    logging.basicConfig()
    
    # Load sample configuration 
    cfg = Config(sys.argv[1])
    
    # Update the request information 
    cfg.request.uid = sys.argv[2]
    cfg.request.name = sys.argv[3]

    # Create the request object and execute 
    req = AuthRequest(cfg)
    req.execute()


INSTALLATION 
============

# Ubuntu 
$ sudo apt-get install python-dev libxml2-dev libxslt1-dev libxmlsec1 libxmlsec1-dev 
$ sudo pip install lxml pyxmlsec libxml2 M2Crypto 
$ easy_install pyAadhaarAuth
$ cat auth.cfg 
$ python aadhaarclient.py

STATUS
======

1. Skeleton code (not production-ready) 
2. Simplest possible XSD-compliant XML is generated for request and response 
3. Incoming XML can be validated and 'objectified for both 
4. Outgoing XML can be signed (and verified using p12 file)
5. Has support for generation of Pid XML (biometric and demographic)
6. Session key automatically generated and 
7. Encryption of session key using UID certificate
(and encryption/decryption testing using public.p12) 
8. Support for license key in the config file
9. Support for posting to authentication server and receiving the response 
10. AES encryption and decryption support added 

TODO
====

0. Integration and cleanup. 
1. Look through the GeoAmida implementation to see the differences
in implementation - mostly done 
2. Figure out how to invoke xmlDocDumpFormatMemory instead of 
lxml.tostring and doc.formatDump. Not sure for now. Not sure 
that it matters. 
3. Use the objectified xml to populate internal state 
4. Look through the spec for validation rules beyond what the 
XSD is providing (e.g., sanity checks) 
5. Look into integration with biometrics
6. Fix fixtures/call_parameters.json 
7. Add support for session key generation and extraction of 
certificate information - done
8. Make this into a module - in progress 
9. Test with https connection 
10. A batch-mode operation 
11. Performance evaluation/statistics 


THANKS
======

UIDAI - for authentication spec and a bold initiative
Mindtree - for the sample java client 
GeoDesic - for c-code 

