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

NEW!!! We have a new document discussing [AUA Design and Implementation](https://github.com/pingali/pyAadhaarAuth/raw/master/docs/AUA_Design_and_Implementation.pdf)


Latest Release
--------------

  * Alpha Release (0.2) Nov 28, 2011 
  * Supported platform: Linux (Ubuntu) 

Features
--------

  * Support for both biometrics and demographics
  * Simple API 
  * Sample clients for single or batch requests 
  * Sample AUA client and servers 
  * Automatic validation checks - UID numbering scheme, XSD compliance,
    encryption, and other checks    
  * Extensive debugging information 
  * Basic performance information 
  * Easy configuration 

Example
-------

The following client takes the default configuration file and performs
the authentication request. This client is installed as
aadhaar-sample-client for testing and development. See instructions
below.

>        
>        """
>        Simplest possible python client
>        """
>        import logging
>        import sys, os, os.path 
>        from config import Config 
>        log = logging.getLogger("SampleClient")
>        
>        from AadhaarAuth.request import AuthRequest
>        from AadhaarAuth.data import AuthData
>        from AadhaarAuth.command import AuthConfig
>        
>        if __name__ == '__main__':
>            
>            cmd = AuthConfig() 
>            cfg = cmd.update_config() 
>        
>            logging.getLogger().setLevel(cfg.common.loglevel) 
>            logging.basicConfig()
>            
>            # => Force only demographic authentication
>            cfg.request.demographics = ["Pi"]
>            cfg.request.biometrics = []
>            
>            # => Simulate a POS site and generate the request data
>            data = AuthData(cfg=cfg) 
>            data.generate_client_xml() 
>            exported_data = data.export_request_data() 
>        
>            # Create the request object and execute the auth request
>            req = AuthRequest(cfg)
>            req.import_request_data(exported_data)
>            req.execute()
> 
>            # Extract the response            
>            data = json.loads(req.export_response_data())
>            res = AuthResponse(cfg=cfg, uid=cfg.request.uid) 
>            res.load_string(data['xml'])
>             
>            #Print the response
>            bits = res.lookup_usage_bits()
>            print "[%.3f] (%s) -> %s " % (data['latency'], bits, data['ret'])
>            if data['err'] is not None and data['err'] != -1: 
>                  print "Err %s: %s "% ( data['err'], data['err_message'])


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
>        $ wget --no-check-certificate -O pyAadhaarAuth.tar.gz https://github.com/pingali/pyAadhaarAuth/tarball/v0.1.0
>        $ tar zxvf pyAadhaarAuth.tar.gz  
>        $ cd pingali-pyAaadhaarAuth-bf47789
>        $ sudo python setup.py install    

Once installed populate the working directory with a simple client and
additional configuration files. Then perform the first authentication
request. 

>         
>        $ cd $WORK 
>        $ aadhaar-generate-client.py .      

This will install a sample client, certificates and configuration
files. Now run the client with the config file. The sample client by
default does only demographic authentication.

>        
>        $ ./aadhaar-sample-client.py  fixtures/auth.cfg 
>        [1.031 secs] (999999990019,Exact(name))  -> y 

You can also override the default parameters as follows:

>        
>        $ ./aadhaar-sample-client.py  fixtures/auth.cfg request.uid=999999990019 request.Pi.name="Shivshankar Choudhury"     
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

Run the ASA server in the background and issue a request from the ASA
client.

>       $ aadhaar-asa-server.py fixtures/auth.cfg  &       
>       $ aadhaar-asa-client.py  fixtures/auth.cfg 999999990019 "Shivshankar Choudhury"     
>       [1.134 secs] (999999990019,Exact(name)(Finger Prints))  -> y 
>       {"err_message": "No error", "err": -1, "ret": "y"}


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

Configuration file 
------------------

The configuration file is a simple json-like file having a series of
elements. There is one common element and several class-specific
elements (e.g., crypt for AuthCrypt class). Since there are multiple
possible configurations (e.g., testing, verification, staging), the
single class-specific element is made to point to one of the possible
configurations using Python Config cross-reference syntax
($<element-name>). 

Request is the most complex configuration given the number of input
parameters. 

The list of attributes that must be included in the authentication
request is specified using the 'demographics' and 'biometrics'
elements. For each of the attributes, there is a corresponding hash
specifying the details. For example, the following specifies exact
match for the name and a threshold match for finger print minutae.

    demographics: ["Pi"]
    biometrics: ["FMR"] 
    Pi: { name: 'Sanjay', ms: 'E'} 
    FMR: { bio: 'DAHS132...' } 

The configuration file is evolving. For the most recent common and
module-specific configuration, please see the [auth.cfg][authurl]

[authurl]: https://github.com/pingali/pyAadhaarAuth/blob/asa-version/AadhaarAuth/fixtures/auth.cfg

AUA Support
-----------

The distribution include sample AUA client and server. 

The AUA client is a modified version of the sample client. It
generates XML using the parameters provided by the resident. Required
data is sent to the AUA server as per the protocol given below. The
client 'posts' JSON object to the server. The response from the server
is a JSON object as well. 

The AUA server first imports data from the JSON object. It then
extracts the client-generated XML and fills it with attributes such as
AUA code and license key. It signs and posts the XML to the UIDAI
server. The AUA server extracts information from the response,
constructs JSON object and responds to the client with this object.
The current implementation of the AUA server is based on Cherrypy, a
light-weight http server and does not incorporate any security. 


AUA Protocol 
------------

The code implements a simple protocol between the POS client that
captures the information and the AUA server that packages the
information and communicates with the authentication server. 

POS Client to AUA server message contains: 
	 
	1. UID 
        2. Unsigned XML (all data is encrypted) 
        3. Demographic hash 

The AUA server inserts auth attributes such as ac, sa, lk and
transaction id before sending it over to the auth server. 

AUA server to POS Client response contains: 

        1. Result 
        2. Error code 
        3. Error message 

The error is specific to the protocol implemented but for now 
reuses the UIDAI error codes 

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

