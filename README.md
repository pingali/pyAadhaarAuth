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

Install dependencies 

>         
>        $ sudo apt-get install python-dev libxml2-dev libxslt1-dev libxmlsec1    
>        $ sudo apt-get install libxmlsec1-dev    
>        $ sudo pip install lxml pyxmlsec libxml2 M2Crypto    

Prepare working directory 

>         
>        $ mkdir auth-client   
>        $ WORK='pwd'/auth-client   

Install from repository. We will distribute it using Pypi once the
code stabilizes.

>         
>        $ cd /tmp   
>        $ wget --no-check-certificate -O pyAadhaarAuth.zip https://github.com/pingali/pyAadhaarAuth/zipball/master   
>        $ unzip pyAadhaarAuth.zip    
>        $ cd pyAadhaarAuth/pingali-pyAaadhaarAuth-a18142   
>        $ sudo python setup.py install    

Once installed populate the working directory with a simple client and
additional configuration files. Then perform the first authentication
request. 

>         
>        $ aadhaar-generate-client.py .      

This will install a sample client, certificates and configuration files. Now run the client. 

>        
>        $ ./aadhaar-sample-client.py  fixtures/auth.cfg 999999990019 "Shivshankar Choudhury"     
>        (999999990019,{'xml': '/tmp/request.xml', 'signedxml': '/tmp/request.xml.sig', 'Pi': {'name': 'Shivshankar Choudhury', 'ms': 'E'}, 'uid': '999999990019', 'demographics': ['Pi'], 'xmlcleanup': True, 'biometrics': [], 'command': 'generate', 'analyze': True}) -> y

'y' shows successful authentication. Note that this client is capable
of doing both demographic and biometric authentication but only does
demographic for now. You can enable biometric authentication by
uncommenting the relevant lines in the sample client. The parameters for the command line are valid testing values provided by UIDAI on their site.

Now run the batch client. Valid test data from the UIDAI site is
stored in fixtures/test_data.json and the file already specified in
auth.cfg file. In this case you can run the script installed by the
package in /usr/local/bin (on Linux).

>          
>       aadhaar-batch-client.py fixtures/auth.cfg 
>       (999999990019,{'xml': '/tmp/request.xml', 'signedxml': '/tmp/request.xml.sig', 'Pi': {'name': u'Shivshankar Choudhury', 'ms': 'E'}, 'uid': u'999999990019', 'demographics': ['Pi'], 'FMR': {'bio': u'Rk1SACAyMAAAAADkAAgAyQFnAMUAxQEAAAARIQBqAGsgPgCIAG0fRwC2AG2dSQBVAIUjPABuALShMgCxAL0jMAByAM6lPgCmAN2kQQBwAN8qNAB1AN8mPADJAOcgOQA8AOorNABoAOomOQC+AO2fMQDFAPqlSgCvAP8lRQB8AQuhPABwAQ4fMgB7ASqcRADAAS4iNwCkATMeMwCFATYeNwBLATYwMQBWATcoMQCkATecMQBEATwyMgBJAUciQQCkAU8cNQB9AVQWNgCEAVUVRACoAVgYOgBBAV69NgCsAWeYNwAA'}, 'xmlcleanup': True, 'biometrics': ['FMR'], 'command': 'generate', 'analyze': True}) -> y
>       (999999990026,{'xml': '/tmp/request.xml', 'signedxml': '/tmp/request.xml.sig', 'Pi': {'name': u'Kumar Agarwal', 'ms': 'E'}, 'uid': u'999999990026', 'demographics': ['Pi'], 'FMR': {'bio': u'Rk1SACAyMAAAAADkAAgAyQFnAMUAxQEAAAARIQBqAGsgPgCIAG0fRwC2AG2dSQBVAIUjPABuALShMgCxAL0jMAByAM6lPgCmAN2kQQBwAN8qNAB1AN8mPADJAOcgOQA8AOorNABoAOomOQC+AO2fMQDFAPqlSgCvAP8lRQB8AQuhPABwAQ4fMgB7ASqcRADAAS4iNwCkATMeMwCFATYeNwBLATYwMQBWATcoMQCkATecMQBEATwyMgBJAUciQQCkAU8cNQB9AVQWNgCEAVUVRACoAVgYOgBBAV69NgCsAWeYNwAA'}, 'xmlcleanup': True, 'biometrics': ['FMR'], 'command': 'generate', 'analyze': True}) -> y
>       (999999990042,{'xml': '/tmp/request.xml', 'signedxml': '/tmp/request.xml.sig', 'Pi': {'name': u'Fatima Bedi', 'ms': 'E'}, 'uid': u'999999990042', 'demographics': ['Pi'], 'FMR': {'bio': u'Rk1SACAyMAAAAADkAAgAyQFnAMUAxQEAAAARIQBqAGsgPgCIAG0fRwC2AG2dSQBVAIUjPABuALShMgCxAL0jMAByAM6lPgCmAN2kQQBwAN8qNAB1AN8mPADJAOcgOQA8AOorNABoAOomOQC+AO2fMQDFAPqlSgCvAP8lRQB8AQuhPABwAQ4fMgB7ASqcRADAAS4iNwCkATMeMwCFATYeNwBLATYwMQBWATcoMQCkATecMQBEATwyMgBJAUciQQCkAU8cNQB9AVQWNgCEAVUVRACoAVgYOgBBAV69NgCsAWeYNwAA'}, 'xmlcleanup': True, 'biometrics': ['FMR'], 'command': 'generate', 'analyze': True}) -> y
>       (999999990057,{'xml': '/tmp/request.xml', 'signedxml': '/tmp/request.xml.sig', 'Pi': {'name': u'Rohit Pandey', 'ms': 'E'}, 'uid': u'999999990057', 'demographics': ['Pi'], 'FMR': {'bio': u'Rk1SACAyMAAAAADkAAgAyQFnAMUAxQEAAAARIQBqAGsgPgCIAG0fRwC2AG2dSQBVAIUjPABuALShMgCxAL0jMAByAM6lPgCmAN2kQQBwAN8qNAB1AN8mPADJAOcgOQA8AOorNABoAOomOQC+AO2fMQDFAPqlSgCvAP8lRQB8AQuhPABwAQ4fMgB7ASqcRADAAS4iNwCkATMeMwCFATYeNwBLATYwMQBWATcoMQCkATecMQBEATwyMgBJAUciQQCkAU8cNQB9AVQWNgCEAVUVRACoAVgYOgBBAV69NgCsAWeYNwAA'}, 'xmlcleanup': True, 'biometrics': ['FMR'], 'command': 'generate', 'analyze': True}) -> y

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
    4. Look through the spec for validation rules beyond what the XSD is providing (e.g., sanity checks)    
    5. Explore browser and mobile phone support 

Thanks 
------   

  * UIDAI      - For authentication spec and a bold initiative
  * TCS        - For support    
  * Mindtree   - For the sample java client    
  * GeoDesic   - for c-code    
  * Viral Shah - Feedback and testing    
  * Python community - For a great development platform 
