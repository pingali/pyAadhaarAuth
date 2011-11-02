================================================
Python Client for Aadhaar Authentication Service
================================================

*THIS IS STILL UNDER DEVELOPMENT. DO NOT USE IT YET" 

This package supports biometrics and demographics authentication
using the Aadhaar Authentication Service (also known as UID).

FEATURES
========

Mostly a wishlist right now. By Python will help achieve a 
lot of these painlessly. 

1. Easy configuration file
2. Automatic XSD validation and other checks 
3. Cross platform 
4. Integration with web applications 

USAGE 
=====

Please obtain the relevant certificates from UIDAI 
(https://developer.uidai.gov.in)

Expected usage pattern is follows (TBD)

$ cat aadhaarclient.py 
#!/usr/bin/env python

from AadhaarAuth import AuthRequest, AuthResponse
from config import Config
 
cfg = Config("auth.cfg")
areq = AuthRequest(cfg) 
ares = AuthResponse(cfg) 

while more_authentications: 
    areq.set_uid("12323232") 
    areq.set_demographics("Name", "Utkal Chaudhury")
    result = auth.execute() 
    ares.load(result)
    auth.clear()
     
INSTALLATION 
============

# Ubuntu 
$ sudo apt-get install python-dev libxml2-dev libxslt1-dev libxmlsec1 libxmlsec1-dev 
$ sudo pip install lxml pyxmlsec libxml2 
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

TODO
====

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

Running 
======

$ python authrequest.py 
<Auth txn="" ac="public" xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" ver="1.5" uid="123412341234" tid="" sa="public">
  <Skey ci="23233">ZWhoc2tz</Skey>
  <Uses pfa="n" bio="n" pin="n" pa="n" otp="n" pi="y"/>
  <Data>ZGZkc2ZkZmRz</Data>
</Auth>

The XML generated is XSD compliant
Validating this incoming XML
<?xml version="1.0"?> 
<Auth xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" 
      ver="1.5" tid="public" ac="public" sa="public" 
      lk="MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=" uid="999999990019" 
      txn="GEO.11051880"> 
      <Skey ci="20131003">Nc6DrZKFk1oQXxfgnFUl0mmtYYIPl0RGaFd2oINkpChU1++xdddMx6Dlbz6mEYs3 
            IyzChGjRXN5/al9r0runFX8LspTfMchwpxaaDIOyIUguBoYmPUqJDqTQcwey6Ntc 
            TJWFSgOvBg+omUkdbK/9GOQ5KWWrN+E0A9JN0IPU4IJqJZmsA6ETZlVoZteYtoMI 
            Ucv53qmxNPOEmJ3s4BC3ppHRRWRFMUp/eW7DFJ33W+uInZB6yekKE0dz8fYeo03w 
            2JUT1wlafL7aseb04nv5tNEbllHWafmbMpbv2pXKr+WPgytjrygt1LagGqF4a5Mr 
            /UTNwsy4m/YwlkWN0QcYVw== 
      </Skey> 
      <Uses otp="n" pin="n" bio="n" pa="n" pfa="n" pi="y" /> 
      <Data>YOn05vg5qMwElULpEmdiH0j6rM1XWcbQN0n+CFNQeazouCgjyPBH/a2SwbFgq/fF 
            CYUm+the8gQyYC36VO49NLcNcD7WdMhweoiDYgJoCX/t87Kbq/ABoAetfX7OLAck 
            /mHrTmw8tsfJgo4xGSzKZKr+pVn1O8dDHJjwgptySr7vp2Ntj6ogu6B905rsyTWw 
            73iMgoILDHf5soM3Pvde+/XW5rJD9AIPQGhHnKirwkiAgNIhtWU6ttYg4t6gHHbZ 
            0gVBwgjRzM3sDWKzK0EnmA== 
      </Data> 
      <Hmac>xy+JPoVN9dsWVm4YPZFwhVBKcUzzCTVvAxikT6BT5EcPgzX2JkLFDls+kLoNMpWe 
      </Hmac> 
</Auth> 

The XML generated is XSD compliant

$ python authresponse.py
<?xml version="1.0"?>
<AuthRes info="" txn="" code="-1" err="100" ts="2011-10-30T13:30:35" ret="n" xmlns="http://www.uidai.gov.in/authentication/uid-auth-response/1.0"/>

The XML generated is XSD compliant
Validating this incoming XML
<?xml version="1.0"?> 
<AuthRes  xmlns="http://www.uidai.gov.in/authentication/uid-auth-response/1.0"
	  ret="y" code="52" 
	  txn="322hfdjhsjkdhfjkds" err="100" info="" 
	  ts="2011-10-30T13:26:19"></AuthRes>

The XML generated is XSD compliant

$ python authrequest_signature.py fixtures/authrequest-with-sig.xml 
<?xml version="1.0"?>
<Auth xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" ver="1.5" tid="public" ac="public" sa="public" lk="MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=" uid="999999990019" txn="GEO.11051880"> 
....
R/l8w0hCInLusQMZeXgHcnxBGDSk1AQxKk5UfQmCwHNcRJMB5Zkj8+9n6T+/wx6D
tKDelktgIoo7w0EJ6MdVJ9Qzr5PJcYzX+ERgJEd/NNNVoPjFc2Al2odjToZdFN8+
/upJnBH02TRb1Wq63OtcuyBIFA==</X509Certificate>
</X509Data> 
            </KeyInfo> 
      </Signature> 
</Auth>

$ python authrequest_signature.py fixtures/authrequest-with-sig.xml  > new-authrequest-with-sig.xml
$ xmlsec --verify --pkcs12 fixtures/public.p12 --pwd public new-authrequest-with-sig.xml
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/C=IN/ST=KA/L=Bangalore/O=Public AUA/OU=Public/CN=Public AUA;err=20;msg=unable to get local issuer certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/C=IN/ST=KA/L=Bangalore/O=Public AUA/OU=Public/CN=Public AUA;err=20;msg=unable to get local issuer certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=20;msg=unable to get local issuer certificate
OK
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0

[Notes: The above error refers to the lack of CA certificate.] 

$ python auth_crypt.py 
certificate expiry =  Jun 28 04:40:44 2012 GMT
Encryption payload:  39jsjsfdhdshfd
Encrypted base64 encoded data:
hm8IKZIubO49F3y2RiLhBlW1tG3lAWep4j9l8rQ/XO/0OHKj4s+iehkkUw6Ew5KGes/yWeo993SRYw4/4sGT+fSNqCGw0LCL7WGdDKxuuoTuW0qytdfQQCydPICo1/fyy6RNl9n/v4+4eaf3UWgfg3oFq3d4J4cSDqfHC4ToCeQ=
Decrypted data
39jsjsfdhdshfd
Encrytion payload and decrypted data matched

$python auth_connection.py
<?xml version="1.0" encoding="UTF-8"?><AuthRes code="7f27e1ab8ec7480593835102b0582f44" err="931" info="015feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e90000000000000000000000000000000000000000000000000000000000000000100000000000" ret="n" ts="2011-11-02T14:22:16.916+05:30" txn=""><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>9dhWVTdnfu/DsYzZuHHGOClWWdDnY/FavATpmmAKpmI=</DigestValue></Reference></SignedInfo><SignatureValue>nerrU3qgtbVOJ8MroHpTT1vLf0CC4qZortlLk3XEu3FJbAgAA9TIFtBPQ1Bo6CrLjX9izlmkLukp
rw7KiEhqkEf8hfyi+MAhcGhFrt3Tt0AyO2ZnHi3SzgFpJGj43wT35gYYPN7yZ5ZSDcNan8AR9Y1r
K8rwnnifyYekDQzjvwMsEdTmdY3UYiTwzxUIYTiZ+1QY+9Air6WqRX3SPr3qAqf/k4mQNgp8oklH
jQNOsS/7J0kZhLGDXUUi5MW8y5BjLxGTOQsTQBikWoYncXzic6e3V/eKMVh3UBbZzZYAdStYUXui
JUU0ryKIXy88SAkjGbb4jPILBw7yQRS7h7UYkw==</SignatureValue></Signature></AuthRes>


THANKS
======

UIDAI - for authentication spec and a bold initiative
Mindtree - for the sample java client 
GeoDesic - for c-code 

