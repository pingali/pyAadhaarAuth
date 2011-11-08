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

>    $ sudo apt-get install python-dev libxml2-dev libxslt1-dev libxmlsec1    
>    $ sudo apt-get install libxmlsec1-dev    
>    $ sudo pip install lxml pyxmlsec libxml2 M2Crypto    

Prepare working directory 

>    $ mkdir auth-client   
>    $ WORK='pwd'/auth-client   

Install from repository. We will distribute it using Pypi once the
code stabilizes.

>    $ cd /tmp   
>    $ wget --no-check-certificate -O pyAadhaarAuth.zip https://github.com/pingali/pyAadhaarAuth/zipball/master   
>    $ unzip pyAadhaarAuth.zip    
>    $ cd pyAadhaarAuth/pingali-pyAaadhaarAuth-a18142   
>    $ sudo python setup.py install    

Once installed populate the working directory   

>    $ mkdir $WORK/fixtures    
>    $ cp AadhaarAuth/fixtures/auth.cfg $WORK/fixtures     
>    $ cp AadhaarAuth/fixtures/public\* $WORK/fixtures    
>    $ cp AadhaarAuth/fixtures/uidai_auth_stage\* $WORK/fixtures    
>    $ cp AadhaarAuth/simple-client.py $WORK   
>    $ cd $WORK    
>    $ python simple-client.py fixtures/auth.cfg    

Work-in-progress    
----------------

  1. Use the objectified xml to populate internal state    
  2. Look through the spec for validation rules beyond what the    
     XSD is providing (e.g., sanity checks)    
  3. Look into integration with biometrics   
  4. Test with https connection    
  5. Performance evaluation/statistics    


Thanks 
------   

  * UIDAI      - For authentication spec and a bold initiative
  * TCS        - For support    
  * Mindtree   - For the sample java client    
  * GeoDesic   - for c-code    
  * Viral Shah - Feedback and testing    
