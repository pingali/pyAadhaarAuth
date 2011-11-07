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

import logging 
import dumper 
import hashlib, hmac, base64, random 
from config import Config 
import traceback 
from datetime import datetime
from M2Crypto import Rand 
import re

from crypt import AuthCrypt 
from signature import AuthSignature
from validate import AuthValidate
from connection import AuthConnection 
from response import AuthResponse

log=logging.getLogger("AuthRequest")

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
        self._result = {
            '_request_unsigned_xml': None, 
            '_request_signed_xml': None,
            '_response_signed_xml': None
            }

        self._checker = AuthValidate(cfg=self._cfg, 
                                     request_xsd=self._cfg.common.request_xsd,
                                     testing=True) 

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
        
        #=> Set the session key 
        self._session_key = Rand.rand_bytes(self._cfg.common.rsa_key_len) 
        log.debug("session_key (encoded) = %s" % base64.b64encode(self._session_key))
        encrypted_session_key = a.x509_encrypt(self._session_key)
        self._skey['_text'] = base64.b64encode(encrypted_session_key)

        when = a.x509_get_cert_expiry() #Jun 28 04:40:44 2012 GMT
        expiry = datetime.strptime(when, "%b %d %H:%M:%S %Y %Z")
        self._skey['_ci'] = expiry.strftime("%Y%m%d")


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
            
        #log.debug("Setting data = %s" % data)

        x = AuthCrypt(cfg=self._cfg) 
        encrypted_pid = x.aes_encrypt(key=self._session_key, msg=data)
        self._data = base64.b64encode(encrypted_pid)
        log.debug("Data = %s " % self._data)

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
        
        log.debug("data len = %d " % len(data))
        # This should be digest and not hexdigest 

        hash_digest = hashlib.sha256(data).digest()
        log.debug("Sha256 of data (encoded) = %s" %\
                      base64.b64encode(hash_digest))

        x = AuthCrypt(cfg=self._cfg) 
        encrypted_hash = x.aes_encrypt(key=self._session_key, 
                                       msg=hash_digest)
        self._hmac = base64.b64encode(encrypted_hash) 
        log.debug("Hmac = %s " % self._hmac)
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
        self._pidxml_biometrics = etree.tostring(doc,pretty_print=False)
        
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
        self._pidxml_demographics = etree.tostring(doc,pretty_print=False)
        
        log.debug("Pid XML = %s " % self._pidxml_demographics)
        
        # => Follow the auth client. Construct the entire xml and then
        # extract the demographic substring
        p = re.compile("<Demo.*/Demo>", re.MULTILINE) 
        demo_match_obj=p.search(self._pidxml_demographics)
        if (demo_match_obj == None):
            demo_string = ""
        else:
            demo_string = demo_match_obj.group(0)
        if (len(demo_string) < 64):
            # The java seems to be right justifying and left padding
            # with 0s. However when I do that, the hashes are not matching
            # with the response that the server sends. 
            
            #demo_xml = demo_string.rjust(64, "0")
            demo_xml = demo_string
        else:
            demo_xml = demo_string
        log.debug("Demographics string = %s " % demo_xml)

        # This will enable checking the response string
        self._demo_hash = hashlib.sha256(demo_xml).hexdigest()
        log.debug("PID demographics hash = %s " % self._demo_hash)
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
        return ("<?xml version=\"1.0\"?>\n%s" %(etree.tostring(doc, pretty_print=False)))
    
    def analyze_xmls(self): 
        """
        Analyze the XML being sent to the server
        """ 

        pid_content_sizes = \
            self._checker.analyze(xml=self._pidxml_demographics,
                            is_file=False) 
        signed_content_sizes = \
            self._checker.analyze(xml=self._result['_request_signed_xml'],
                            is_file=False) 
        log.debug("Payload (Pid) Element:")
        log.debug(pid_content_sizes)
        log.debug("Fully Signed XML:")
        log.debug(signed_content_sizes)

    def sign_request_xml(self,xml=None, update_state=True): 
        """
        Sign the payload XML provided (or extracted from self._result)
        """
        
        cfg = self._cfg 
        
        if xml == None: 
            xml = self._result['_request_unsigned_xml'] 
            
        if (xml == None): 
            log.debug("XML to be signed = %s " % xml)
            raise Exception("Could not find XML to sign")
        
        log.debug("Signing %s ... %s " %(xml[1:20],xml[len(xml)-20:len(xml)]))

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
        sig = AuthSignature() 
        sig.init_xmlsec() 
        res = sig.sign_file(tmpfp_unsigned, 
                            tmpfp_signed, 
                            cfg.common.pkcs_path, 
                            cfg.common.pkcs_password)
        sig.shutdown_xmlsec() 
        if (res == 1): 
            log.debug("Signed successfully!")
        else: 
            log.debug("Signing unsuccessful for some reason \"%s\""  % res)
            raise Exception("Unsuccessful signature") 

        signed_content = file(tmpfp_signed).read() 
        log.debug("Signed XML (%s):\n%s" % (tmpfp_signed, signed_content))
        return signed_content 

    def execute(self): 
        """
        Execute the query specified in the configuration file. 
        """
        
        cfg = self._cfg 

        # Initialization
        self.set_txn()

        # XXX Here there should be a check for biometrics 
        self.set_pidxml_demographics(data=cfg.request.name)
        
        # => Elements of the final XML 
        self.set_skey() 
        self.set_data()
        self.set_hmac() 
        
        # => Extract and store the result 
        self._result['_request_unsigned_xml'] = self.tostring()  # dump it 
        
        log.debug("Unsigned XML:")
        log.debug(self._result['_request_unsigned_xml'])
    
        # =>  Now validate the xml generated 
        res = self._checker.validate(self._result['_request_unsigned_xml'], 
                               is_file=False, signed=False)
        if (res == False): 
            log.debug("Invalid XML generated")
        
        #=> In testing mode extract the XML to see if we can get back
        # the origin XML 
        if (cfg.common.mode == "testing"):
            res = self._checker.extract(xml=xml,
                                  is_file=False,
                                  key=cfg.common.private_key)
        
        #=> Sign the request
        signed_xml = self.sign_request_xml()         
        self._result['_request_signed_xml'] = signed_xml
        
        #=> Log.Debug(stats about the generated XMLs 
        if cfg.request.analyze: 
            self.analyze_xmls() 

        # Validate the signed file 
        valid = self._checker.validate(self._result['_request_signed_xml'], 
                               is_file=False, signed=True)
        if valid: 
            log.debug("Validated XML generated with result = %s " % res)
        
        # Testing will use the local cert instead of UIDAI's public
        # cert for encryption. Therefore will fail the tests at the
        # authentication server.
        
        if (cfg.common.mode != "testing"):
            log.debug("Connecting to the server...") 
            conn = AuthConnection(cfg, ac=cfg.common.ac)
            try: 
                xml = conn.authenticate(uid=cfg.request.uid, 
                                        data=self._result['_request_signed_xml']) 
            except: 
                traceback.print_exc(file=sys.stdout)
                raise Exception("Unable to complete authentication")
                
            log.debug("Response from Auth Server")
            log.debug(xml)
            res = AuthResponse(cfg=cfg, 
                               uid=cfg.request.uid)

            res.load_string(xml) 
            log.debug("Match result = %s " % res.get_ret())
            log.debug("Error = %s " % res.lookup_err())
            log.debug("Flags that are set: %s " % res.lookup_usage_bits())
            log.debug("UID Hash = %s " % res.get_uid_hash())
            log.debug("Request uid hash = %s " % req.get_uid_hash())            
            log.debug("Demo hash = %s " % res.get_demo_hash())
            log.debug("Request Demo hash = %s " % req.get_demo_hash())
            
        else:
            log.debug("Skipping contacting the server in the 'testing' mode")
            log.debug("Please change cfg >> common >> mode to enable server posting")

        # Now cleanup 
        if (cfg.request.xmlcleanup is True): 
            os.unlink(tmpfp_unsigned) 
            os.unlink(tmpfp_signed)
        
        
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
    
    #=> Setup logging 
    logging.basicConfig(
	filename='execution.log',
	format='%(asctime)-6s: %(name)s - %(levelname)s - %(message)s')

    log.setLevel(logging.DEBUG)
    log.info("Starting my AuthClient")

    if cfg.request.command == "generate": 

        # => Generate the XML file 
        req = AuthRequest(cfg=cfg, 
                          uid=cfg.request.uid, 
                          ac=cfg.common.ac)
        req.execute() 

    elif (cfg.request.command == "validate"): 

        checker = AuthValidate(cfg=cfg, 
                               request_xsd=cfg.common.request_xsd,
                               testing=True) 

        # Validate the signed file 
        tmpfp_signed = cfg.request.signedxml
        res = checker.validate(tmpfp_signed, 
                               is_file=True, 
                               signed=True)
        log.debug("Validated XML generated with result = %s " % res)

    elif (cfg.request.command == "extract"): 
        checker = AuthValidate(cfg=cfg, 
                               request_xsd=cfg.common.request_xsd,
                               testing=True) 
        # Now extract the contents 
        res = checker.extract(xml=cfg.request.xml,
                              is_file=True,
                              key=cfg.common.private_key)
        log.debug("Extracted XML with result = %s " % res)
    else: 
        raise Exception("Unknown command") 
    
