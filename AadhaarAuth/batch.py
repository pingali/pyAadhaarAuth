#!/usr/bin/env python
#
#Copyright (C) 2011 by Venkata Pingali (pingali@gmail.com) & TCS 
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

import os, sys
sys.path.append("lib") 

import tempfile 
import dumper 
import hashlib, hmac, base64, random 
from config import Config 
import traceback 
from datetime import datetime
from M2Crypto import Rand 

from crypt import AuthCrypt 
from signature import AuthRequestSignature
from validate import AuthValidate
from connection import AuthConnection 
from response import AuthResponse
from request import AuthRequest

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"


"""
Issue batch requests to the server
"""
class AuthBatchRequest():

if __name__ == '__main__':
       
    assert(sys.argv)
    if len(sys.argv) < 2:
        print """
Error: command line should specify a config file.

Usage: batch.py <config-file>

$ cat example.cfg 
common: { 
    mode: 'testing',

    # Specific to this AuA
    license_key:  "MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=",
    private_key: 'fixtures/public_key.pem',  # note that public refers to
    public_cert: 'fixtures/public_cert.pem', # public AuA 
    pkcs_path: "fixtures/public.p12",
    pkcs_password: "public",
    uid_cert_path: "fixtures/uidai_auth_stage.cer",

    # shared by all 
    rsa_key_len: 32, 
    sha256_length: 256,    
    auth_url: 'http://auth.uidai.gov.in/1.5/'    
    request_xsd: 'xsd/uid-auth-request.xsd',
    response_xsd: 'xsd/uid-auth-response.xsd'   

}

batch: { 
    
    json: 'fixtures/test_data.json' 
}

"""
        sys.exit(1) 
    
    cfg = Config(sys.argv[1])

    checker = AuthValidate(cfg=cfg, 
                           request_xsd=cfg.common.request_xsd,
                           testing=True) 
    
    if cfg.request.command == "generate": 

        # => Generate the XML file 
        req = AuthRequest(cfg=cfg, 
                          uid=cfg.request.uid, ac=cfg.common.ac)
        req.set_txn()
        req.set_skey() 
        req.set_pidxml_demographics(data=cfg.request.name)
        #print req._pidxml_demographics 
        req.set_data()
        req.set_hmac() 
        xml = req.tostring()  # dump it 
        
        print "Unsigned XML:"
        print xml
    
        # Now validate the xml generated 
        res = checker.validate(xml, 
                               is_file=False, signed=False)
        if (res == False): 
            print "Invalid XML generated" 
            
        if (cfg.common.mode == "testing"):
            res = checker.extract(xml=xml,
                                  is_file=False,
                                  key=cfg.common.private_key)
        
        # => Store the xml and generated a signed version
        if (cfg.request.xml == None): 
            tmpfp = tempfile.NamedTemporaryFile(delete=False) 
            tmpfp_unsigned = tmpfp.name
        else:
            tmpfp_unsigned = cfg.request.xml
            tmpfp = file(tmpfp_unsigned, 'w')
        tmpfp.write(xml) 
        tmpfp.flush() 
        tmpfp.close() 
        
        #=> Generate the signed version
        if (cfg.request.signedxml == None): 
            tmpfp_signed = cfg.request.signedxml 
        else:
            tmpfp_signed = tmpfp_unsigned + ".sig" 
         
        # => Sign the XML generated
        sig = AuthRequestSignature() 
        sig.init_xmlsec() 
        res = sig.sign_file(tmpfp_unsigned, 
                            tmpfp_signed, 
                            cfg.common.pkcs_path, 
                            cfg.common.pkcs_password)
        sig.shutdown_xmlsec() 
        if (res == 1): 
            print "Signed successfully!"
        else: 
            print "Signing unsuccessful for some reason \"%s\"" %res
            raise Exception("Unsuccessful signature") 

        signed_content = file(tmpfp_signed).read() 
        print "Signed XML (%s):" % tmpfp_signed
        print signed_content 
        
        # Validate the signed file 
        res = checker.validate(tmpfp_signed, is_file=True, signed=True)
        print "Validated XML generated with result = ", res
        
        # Testing will use the local cert instead of UIDAI's public
        # cert for encryption. Therefore will fail the tests at the
        # authentication server.
        
        if (cfg.common.mode != "testing"):
            conn = AuthConnection(cfg, ac=cfg.common.ac)
            try: 
                xml = conn.authenticate(uid=cfg.request.uid, data=signed_content) 
            except: 
                traceback.print_exc(file=sys.stdout)
                print "Found an exception. Unable to complete authentication"
                
            print "Response from Auth Server" 
            print xml 
            res = AuthResponse(cfg=cfg, 
                               uid=cfg.request.uid)


            res.load_string(xml) 
            print "UID Hash = ", res.get_uid_hash() 
            print "Request uid hash = ", req.get_uid_hash() 
            
            print "Demo hash = ", res.get_demo_hash() 
            print "Request Demo hash = ", req.get_demo_hash() 

            res.lookup_error()
            print "Flags that are set: ", res.lookup_usage_bits()
        else:
            print "Skpping contacting the server in the 'testing' mode"
            print "Please change cfg >> common >> mode to enable server posting" 

        # Now cleanup 
        if (cfg.request.xmlcleanup is True): 
            os.unlink(tmpfp_unsigned) 
            os.unlink(tmpfp_signed)

    elif (cfg.request.command == "validate"): 

        # Validate the signed file 
        tmpfp_signed = cfg.request.signedxml
        res = checker.validate(tmpfp_signed, 
                               is_file=True, 
                               signed=True)
        print "Validated XML generated with result = ", res

    elif (cfg.request.command == "extract"): 
        # Now extract the contents 
        res = checker.extract(xml=cfg.request.xml,
                              is_file=True,
                              key=cfg.common.private_key)
        print "Extracted XML with result = ", res
    else: 
        raise Exception("Unknown command") 
    
