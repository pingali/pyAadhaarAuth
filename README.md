Python Client and Library for Aadhaar Authentication Service
------------------------------------------------------------

This python package supports biometrics and demographics
authentication using the Aadhaar Authentication Service (also known as
UID). The library takes care of the details of packaging data and
communicating with the Aadhaar authentication server leaving the
developer to focus on the application, say Aadhaar-enabled payments. 

This implementation is basically compliant with [Aadhaar
authentication API Ver 1.5 (Rev 1)][spec] but is WIP.

[spec]: http://uidai.gov.in/images/FrontPageUpdates/aadhaar_authentication_api_1_5_rev1_1.pdf

The aim of this library is to be a reference implementation of the
Authentication API and at the same time enable rapid development of
Aadhaar-based applications. 

Latest Release
--------------

  * Alpha Release (0.1) Nov 15, 2011 - Planned 
  * Supported platform: Linux (Ubuntu) 

Features
--------

  * Support for both biometrics and demographics
  * Simple API 
  * Sample clients for single or batch requests 
  * Automatic validation checks - UID numbering scheme, XSD compliance,
    encryption, and other checks    
  * Extensive debugging information 
  * Basic performance information 
  * Easy configuration 

Example
-------

Sample client 

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
>          cfg.request.demographics = ["Pi"]
>          cfg.request['Pi'] = {
>                   'ms': "E",
>                   'name': sys.argv[3]
>           }
>      
>          # Create the request object and execute   
>          req = AuthRequest(cfg)   
>          req.execute()   
>     


Installation
------------

Install dependencies. 

>         
>        $ sudo apt-get install python-dev libxml2-dev libxslt1-dev  xmlsec1       
>        $ sudo apt-get install libxmlsec1 swig libxmlsec1-openssl libxmlsec1-dev      
>        $ sudo apt-get install libssl-dev python-openssl      
>        $ sudo easy_install lxml pyxmlsec M2Crypto requests config  

Prepare working directory 

>         
>        $ mkdir auth-client   
>        $ WORK='pwd'/auth-client   

Install from repository. We will distribute it using Pypi once the
code stabilizes.

>         
>        $ cd /tmp   
>        $ wget --no-check-certificate -O pyAadhaarAuth.zip https://github.com/downloads/pingali/pyAadhaarAuth/pyAadhaarAuth-Nov10-alpha.zip
>        $ unzip pyAadhaarAuth.zip    
>        $ cd pingali-pyAaadhaarAuth-aXXXXX
>        $ sudo python setup.py install    

Once installed populate the working directory with a simple client and
additional configuration files. Then perform the first authentication
request. 

>         
>        $ cd $WORK 
>        $ aadhaar-generate-client.py .      

This will install a sample client, certificates and configuration files. Now run the client. 

>        
>        $ ./aadhaar-sample-client.py  fixtures/auth.cfg 999999990019 "Shivshankar Choudhury"     
>        [1.031 secs] (999999990019,Exact(name))  -> y 


'y' shows successful authentication. Note that this client is capable
of doing both demographic and biometric authentication but only does
demographic for now. You can enable biometric authentication by
uncommenting the relevant lines in the sample client. The parameters for the command line are valid testing values provided by UIDAI on their site.

Now run the batch client. Valid test data from the UIDAI site is
stored in fixtures/test_data.json and the file already specified in
auth.cfg file. In this case you can run the script installed by the
package in /usr/local/bin (on Linux).

>          
>       $ aadhaar-batch-client.py fixtures/auth.cfg 
>       [0.974 secs] (999999990019,Exact(name)(Finger Prints))  -> y 
>       [1.011 secs] (999999990026,Exact(name)(Finger Prints))  -> y 
>       [1.026 secs] (999999990042,Exact(name)(Finger Prints))  -> y 
>       [0.973 secs] (999999990057,Exact(name)(Finger Prints))  -> y 


Debugging
---------

Extensive logging is supported by the library to help with easy application development. You can enable it by choosing appropriate python logging parameters. For example the logging commands in the sample client file can be replaced by: 

>        
>       logging.getLogger().setLevel(logging.DEBUG) 
>       logging.basicConfig(
> 	                    filename='execution.log', 
>                           format='%(asctime)-6s: %(name)s - %(levelname)s - %(message)s')
>    

Look at execution.log in the local directory once the command is executed. 

Documentation
-------------

Please see docs/apidocs/index.html

Known Issues
------------

     1. SSLv2_Method Error 
     
	If M2Crypto dependencies on OpenSSL are not correct, running
	the client can throw up errors referring to SSLv2_method. In
	that case, check the M2Crypto installation process. Please
	install the latest version from their website.

	http://chandlerproject.org/Projects/MeTooCrypto#Downloads


Work-in-progress    
----------------

  Immediate: 

    1. Integrate the commandline processing with config 
    2. Test with https connection (whenever it is available) 
    3. Performance evaluation/statistics    

  Medium term:  

    1. Language and location support 
	2. Humanize all messages
    3. ASA/AUA split operation model including ASA API development
	4. Use a pregenerated XML as an input
    4. Look through the spec for validation rules beyond what the XSD is providing (e.g., sanity checks)    
    5. Extensive profiling and XML optimizations 
    6. Explore browser and mobile phone support 

Thanks 
------   

  * UIDAI      - For authentication spec and a bold initiative
  * TCS        - For support    
  * Mindtree   - For the sample java client    
  * GeoDesic   - for c-code    
  * Viral Shah - Feedback and testing    
  * Python community - For a great development platform 
