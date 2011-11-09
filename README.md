Python Client and Library for Aadhaar Authentication Service
------------------------------------------------------------

This python package supports biometrics and demographics
authentication using the Aadhaar Authentication Service (also known as
UID).

This implementation is basically compliant with
[Aadhaar authentication API Ver 1.5 (Rev 1)][spec] but WIP. 

[spec]: http://uidai.gov.in/images/FrontPageUpdates/aadhaar_authentication_api_1_5_rev1_1.pdf

Latest Release
--------------

  * Alpha Release (0.1) Nov 15, 2011 - Planned 
  * Platform support: Linux (Ubuntu) and Python 

Features
--------

  * Support for both biometrics and demographics
  * Simple API 
  * Automatic validation checks - UID numbering scheme, XSD compliance,
    encryption, and other checks    
  * Batch processing 
  * Extensive debugging information 
  * Easy configuration file

Example
-------

Download the [sample client][dl] 

[dl]: https://github.com/pingali/pyAadhaarAuth/blob/master/AadhaarAuth/simple-client.py

>         
>         
>      #!/usr/bin/env python     
>      """     
>      Simplest possible python client      
>      """      
>      import logging    
>      import sys    
>      from config import Config    
>      
>      from request import AuthRequest
>      
>      if __name__ == '__main__':   
>          assert(sys.argv)   
>          if len(sys.argv) < 3:   
>              print "Usage: simple-client.py <config-file> <uid> <name>"   
>              print "Please use default config file in fixtures/auth.cfg"    
>              sys.exit(1)    
>      
>          logging.basicConfig()   
>          
>          # Load sample configuration    
>          cfg = Config(sys.argv[1])   
>             
>          # Update the request information    
>          cfg.request.uid = sys.argv[2]   
>          cfg.request.name = sys.argv[3]   
>      
>          # Create the request object and execute   
>          req = AuthRequest(cfg)   
>          req.execute()   
>     


Installation
------------

Install dependencies    

>        $ sudo apt-get install python-dev libxml2-dev libxslt1-dev libxmlsec1    
>        $ sudo apt-get install libxmlsec1-dev    
>        $ sudo pip install lxml pyxmlsec libxml2 M2Crypto    

Prepare working directory 

>        $ mkdir auth-client   
>        $ WORK='pwd'/auth-client   

Install from repository. We will distribute it using Pypi once the
code stabilizes.

>        $ cd /tmp   
>        $ wget --no-check-certificate -O pyAadhaarAuth.zip https://github.com/pingali/pyAadhaarAuth/zipball/master   
>        $ unzip pyAadhaarAuth.zip    
>        $ cd pyAadhaarAuth/pingali-pyAaadhaarAuth-a18142   
>        $ sudo python setup.py install    

Once installed populate the working directory with a simple client and
additional configuration files. Then perform the first authentication
request. 

>        $ aadhaar-generate-client.py . 
>        $ python aadhaar-sample-client.py fixtures/auth.cfg    

Documentation
-------------

Please see docs/apidocs/index.html

Work-in-progress    
----------------

  Immediate: 
  1. Complete address, location and other demographic attributes     
  2. Test with https connection (whenever it is available) 
  3. Performance evaluation/statistics    

  Medium term:  
  1. Language support 
  2. ASA/AUA split operation model 
  3. Use the objectified xml to populate internal state    
  4. Look through the spec for validation rules beyond what the    
     XSD is providing (e.g., sanity checks)    
  5. Explore browser and mobile phone support 

Thanks 
------   

  * UIDAI      - For authentication spec and a bold initiative
  * TCS        - For support    
  * Mindtree   - For the sample java client    
  * GeoDesic   - for c-code    
  * Viral Shah - Feedback and testing    
