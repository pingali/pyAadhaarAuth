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

#
#<?xml version="1.0"?> 
#<Auth xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" 
#      ver="1.5" tid="public" ac="public" sa="public" 
#      lk="MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=" uid="999999990019" 
#      txn="GEO.11051880"> 
#      <Skey ci="20131003">Nc6DrZKFk...
#      </Skey> 
#      <Uses otp="n" pin="n" bio="n" pa="n" pfa="n" pi="y" /> 
#      <Data>YOn05vg5qMwElULpEmdiH0j6rM...
#      </Data> 
#      <Hmac>xy+JPoVN9dsWVm4YPZFwhVBKcUzzCTVvAxikT6BT5EcPgzX2JkLFDls+kLoNMpWe 
#      </Hmac> 
#</Auth> 
#

import os, sys
sys.path.append("lib") 

import tempfile 

#import libxml2
from lxml import etree, objectify 

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

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"


"""
This module implements the authentication request class. We could
potentially move the authentication response class to this module as
well.
"""
class AuthRequest():

    """
    Base class to parse, validate, and generate auth requests going to
    the server. Mostly it will be used in the generate mode. The aim
    is to simplify writing applications around the auth request. We
    could potentially use this with AppEngine and Django that are
    python-based. This interface supports only v1.5 and public AuAs 
    """

    
    def __init__(self, cfg=None, biometrics=False, uid="", 
                 tid="public", lk="", txn="", ac=""):
        """
        Constructor of AuthRequest (see source for more details). 
        
        Set the configuration, flag to indicate whether this is
        biometrics or demographics, and additional addtributes
             
        cfg: Config object (see fixtures/auth.cfg example) (default: None)
        biometrics: Whether this request is for biometrics or not (default: False) 
        uid: uid of the requestor (default="") 
        tid: terminal id (default: "public") 
        txn: transaction id (default: "") 
        lk: License key (if not specified, then config file entry is used) (default: "") 

        """
        self._cfg = cfg 
        if (cfg.common.mode == 'testing'): 
            self._x509_cert = cfg.common.public_cert
        else: 
            self._x509_cert = cfg.common.uid_cert_path

        self._biometrics = biometrics
        if (type(biometrics) != bool):
            raise Exception("Type of biometrics flag should be boolean. Given %s %s " % (type(biometrics), type(True)))

        self._pidxml_biometrics = None
        self._pidxml_demographics = None 
        self._demo_hash = None        
        self._session_key = None
        self._tid = tid
        self._lk = lk
        if (self._lk == ""): 
            self._lk = cfg.common.license_key
            
        if (ac == None or ac == ""): 
            self._ac = "public"
        else:
            self._ac = ac

        self._ver = "1.5" 
        self._sa = "public" 
        self._uid = uid
        self._txn = txn 
        self._skey = { 
            '_ci': None, 
            '_text': None}
        
        #token e.g., mobile number, NFC 
        self._token = { 
            '_type': "",
            '_num': ""
            }

        self._uses  = { 
            '_otp': "n", 
            '_pin': "n",
            '_bio': "n", 
            '_pfa': "n",
            '_pi': "n",
            '_pa': "n",
            }
        self._hmac = ""
        self._data = ""
        self._meta = {
            '_idc': "",
            '_apc': "",
            '_fdc': "",
            }
        self._locn = {
            '_lat': "",
            '_lng': "",
            '_vtc': "",
            '_subdist': "",
            '_dist': "",
            '_state': "",
            '_pc': ""
            }
        
    def get_uid_hash(self): 
        return hashlib.sha256(self._uid).hexdigest() 

    def validate(self): 
        """
        Check for whether the data is complete enough to be able to 
        generate an authentication request. 
        """
        
        # Max length of ac = 10 
        if (self._ac == None or len(self._ac) > 10): 
            raise Exception("Invalid ac. " + 
                            "It is mandatory and maxlength is 10")

        if ((self._skey['_ci'] == None) or (self._skey['_text'] == None)):
            raise Exception("Invalid Skey ci or text")
        
        if (self._pidxml_demographics == None and 
            self._pidxml_biometrics == None):
            raise Exception("Payload (demographics/biometics) not set") 

    
    def set_txn(self, txn=""):
        """
        Update the transaction id 
        """
        if (txn == ""):
            self._txn = "pyAuth:" + self._ac + ":" + random.randint(2**28, 2**32-1).__str__() 


    def set_skey(self):
        """
        Generate the session and set the Skey parameters. 
        """

        a = AuthCrypt(cfg=self._cfg, 
                      pub_key=self._x509_cert,
                      priv_key=None) 

        when = a.x509_get_cert_expiry() #Jun 28 04:40:44 2012 GMT
        expiry = datetime.strptime(when, "%b %d %H:%M:%S %Y %Z")
        self._session_key = Rand.rand_bytes(self._cfg.common.rsa_key_len) 
        print "session_key (encoded) = ", base64.b64encode(self._session_key)
        self._skey['_ci'] = expiry.strftime("%Y%m%d")
        self._skey['_text'] = a.x509_encrypt(self._session_key)

    def get_skey(self):
        """
        Return the Skey 
        """
        return { 
            'ci': self._skey['_ci'],
            'text': self._skey['_text'],
            }

    def set_data(self):
        """
        Set the content of the data element using the pidxml
        generated and stored as part of this class
        """
        if self._biometrics:
            data = self._pidxml_biometrics
        else:
            data = self._pidxml_demographics                

        if (data == None or data == ""): 
            raise Exception("Pid data cannot be empty") 
            
        #print "Setting data = %s" % data 

        x = AuthCrypt(cfg=self._cfg) 
        encrypted_pid = x.aes_encrypt(key=self._session_key, msg=data)
        self._data = base64.b64encode(encrypted_pid)
        print "Data = ", self._data

    def get_data(self):
        return self._data 

    def set_hmac(self): 
        """
        Computes the hmac. Not working yet.
        """
        if self._biometrics:
            data = self._pidxml_biometrics
        else:
            data = self._pidxml_demographics                
        
        # This should be digest and not hexdigest 
        hash_digest = hashlib.sha256(data).hexdigest()
        print "Sha256 of data (encoded) = ", hash_digest

        x = AuthCrypt(cfg=self._cfg) 
        encrypted_hash = x.aes_encrypt(key=self._session_key, 
                                       msg=hash_digest)
        self._hmac = base64.b64encode(encrypted_hash) 
        print "Hmac = ", self._hmac 
        return self._hmac 

    def get_hmac(self):
        return self._hmac 
    
    #<Pid ts="" ver="">
    #  <Meta fdc="" idc="" apc="">
    #	<Locn lat="" lng="" vtc="" subdist="" dist="" state="" pc=""/>
    #  </Meta>
    #  <Demo lang="">
    #	<Pi ms="E|P" mv="" name="" lname="" lmv="" gender="M|F|T" dob="" dobt="V|D|A" age="" phone="" email=""/>
    #	<Pa ms="E" co="" house="" street="" lm="" loc=""
    #	    vtc="" subdist="" dist="" state="" pc="" po=""/> 
    #	<Pfa ms="E|P" mv="" av="" lav="" lmv=""/>
    #  </Demo>
    #  <Bios>
    #	<Bio type="FMR|FIR|IIR" pos="">encoded biometric</Bio>
    #  </Bios>
    #  <Pv otp="" pin=""/>
    #</Pid>

    def set_pidxml_biometrics(self, datatype="FMR", 
                              data=None, ts=None):
        
        """
        Generate the biometrics XML payload. Supports only FMR for now
        """ 

        if (datatype != "FMR"): 
            raise Exception("Non FMR biometrics not supported") 
        
        if (data == None): 
            raise Exception("Data for biometrics inclusion is missing") 

        self._uses['_bio'] = "y"
        self._uses['_bt'] = "FMR"
        
        # the biometrics may be collected somewhere else and the
        # timestamp may be set there. If it not set, set it to 
        # local time 
        if ts == None:
            ts = Datetime.now() 

        root = etree.Element('Pid', 
                             xmlns=self._cfg.common.data_xmlns,
                             ts=ts.strftime("%Y-%m-%dT%H:%M:%S"),
                             ver="1.0")
        bios = etree.SubElement(root, "Bios")
        bio=etree.SubElement(bios, "Bio", type="FMR")
        bio.text = data 
        doc = etree.ElementTree(root) 
        
        # Update internal state 
        self._pidxml_biometrics = etree.tostring(doc,pretty_print=True)
        
        return True 


    def set_pidxml_demographics(self, datatype="Name", 
                                data=None, ts=None):
        """ 
        Generate the demographics XML payload.
        """

        if (datatype != "Name" or data == None):
            raise Exception("Does not support demographic checks other than Name") 
        
        self._uses['_pi'] = "y" 
        
        if ts == None:
            ts = datetime.now() 

        # construct the demographics xml 
        root = etree.Element('Pid', 
                             xmlns=self._cfg.common.data_xmlns, 
                             ts=ts.strftime("%Y-%m-%dT%H:%M:%S"),
                             ver="1.0")
        demo = etree.SubElement(root, "Demo")
        pi=etree.SubElement(demo, "Pi", ms="E", name=data)
        doc = etree.ElementTree(root) 
        
        # update the internal state 
        self._pidxml_demographics = etree.tostring(doc,pretty_print=True)
        
        # text of only the demo object 
        demo_doc = etree.ElementTree(demo)
        demo_string = etree.tostring(demo_doc, pretty_print=False)
        self._demo_hash = hashlib.sha256(demo_string).hexdigest()

        print "PID demographics XML = ", demo_string
        print "PID demographics hash = ", self._demo_hash
        return True 
    
    def get_demo_hash(self):
        return self._demo_hash

    def tostring(self):
        """
        Generate the XML text that must be sent across to the uid
        client.
        """
        self.validate()

        root = etree.Element('Auth', 
                             xmlns=self._cfg.common.request_xmlns,
                             ver=self._ver,
                             tid=self._tid, 
                             ac=self._ac, 
                             sa=self._sa,
                             txn = self._txn,
                             uid = self._uid,
                             lk=self._lk
                             )

        #meta = etree.SubElement(root, "Meta",
        #                        fdc=self._meta['fdc'],
        #                        ipc=self._meta['ipc'],
        #                        apc=self._meta['apc'])
        #txn = etree.SubElement(root, "Txn",
        #                        type=self._txn_elem['_type'],
        #                        num=self._txn_elem['_num'])
        
        skey = etree.SubElement(root, "Skey", ci=self._skey['_ci'])
        skey.text = self._skey['_text']
        
        uses = etree.SubElement(root, "Uses", 
                                otp=self._uses['_otp'],
                                pin=self._uses['_pin'],
                                bio=self._uses['_bio'],
                                pfa=self._uses['_pfa'],
                                pi=self._uses['_pi'],
                                pa=self._uses['_pa'])
        
        data = etree.SubElement(root, "Data")
        data.text = self._data
        hmac = etree.SubElement(root, "Hmac")
        hmac.text = self._hmac

        doc = etree.ElementTree(root) 
        return ("<?xml version=\"1.0\"?>\n%s" %(etree.tostring(doc, pretty_print=True)))
        
if __name__ == '__main__':
       
    assert(sys.argv)
    if len(sys.argv) < 2:
        print """
Error: command line should specify a config file.

Usage: request.py <config-file>

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

request: { 
    
    #=> parameters 
    use_template: False, 

    #=> Input data
    command: "generate",
    uid: "123412341237",
    name: "KKKKK", 
    
    xml: "/tmp/request.xml",
    signedxml: "/tmp/request.xml.sig",
    xmlcleanup: False
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
    
