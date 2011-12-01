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

# Fix the path 
import os, os.path, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/lib")

import tempfile 
#import libxml2
from lxml import etree, objectify 
import logging 
from lib import dumper 
import hashlib, hmac, base64, random 
from config import Config 
import traceback 
from datetime import datetime
from M2Crypto import Rand 
import re
import json

from crypt import AuthCrypt 
from signature import AuthSignature
from validate import AuthValidate
from connection import AuthConnection 
from response import AuthResponse
from data import AuthData 
from command import AuthConfig 

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
    
    
    def __init__(self, cfg=None, uid="", tid="", lk="", txn="", ac="", sa=""):
        """
        Constructor of AuthRequest (see source for more details). 
        
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

        #if (tid == None or tid == ""): 
        #    self._tid = cfg.common.tid
        #else: 
        #    self._tid = tid

        if (lk == None or lk == ""): 
            self._lk = cfg.common.license_key
        else: 
            self._lk = lk 
            
        if (ac == None or ac == ""): 
            self._ac = self._cfg.common.ac 
        else:
            self._ac = ac

        self._ver = self._cfg.common.ver 

        if (sa == None or sa == ""): 
            self._sa = self._cfg.common.sa 
        else: 
            self._sa = sa 

        if (uid == None or uid == ""): 
            self._uid = self._cfg.request.uid
        else: 
            self._uid = uid 

        self._txn = txn         
        self._result = {
            '_request_client_xml': None, 
            '_request_unsigned_xml': None, 
            '_request_signed_xml': None,
            '_response_signed_xml': None
            }
        self._stats = {} 
        self._checker = AuthValidate(cfg=self._cfg, 
                                     request_xsd=self._cfg.common.request_xsd,
                                     testing=(self._cfg.common.mode=='testing'))

    ######################################################
    # Updating and checking internal state 
    ######################################################
            
    def get_uid_hash(self): 
        return hashlib.sha256(self._uid).hexdigest() 

    def set_txn(self, txn=""):
        """
        Update the transaction id 
        """
        if (txn == ""):
            self._txn = "pyAuth:" + self._ac + ":" + random.randint(2**28, 2**32-1).__str__() 

    def get_unsigned_xml(self): 
        return self._result['_request_unsigned_xml']

    def set_unsigned_xml(self, xml): 
        self._result['_request_unsigned_xml'] = xml         

    def get_demo_hash(self):
        return self._demo_hash    

    def get_signed_xml(self): 
        return self._result['_request_signed_xml'] 

    def set_signed_xml(self, xml): 
        self._result['_request_signed_xml'] = xml         

    # This needs to be obtained from the POS 
    def set_demo_hash(self, h):
        self._demo_hash = h 

    def is_successful(self): 
        if self._result['_ret'] == 'y': 
           return True
        else: 
            return False 

    ######################################################
    # Export/import API 
    ######################################################

    def import_request_data(self,jsoned_data): 
        """
        Import data from the client
        """
        data = json.loads(jsoned_data) 
        
        log.debug("Received data from client: %s" % data)

        self._uid = data['uid']
        self._demo_hash = data['demo_hash'] 
        self._result['_request_client_xml'] = data['unsigned_xml'] 

        return True 

    def export_response_data(self): 
        """
        Export the authentication result obtained from the response 
        """
        data = {
            'latency': self._result['_latency'],
            'xml': self._result['_xml'], 
            'ret': self._result['_ret'],
            'err': self._result['_err'],
            'err_message': self._result['_err_message'],
            'ts': self._result['_ts'] ,
            'info': self._result['_info'],
            'txn': self._result['_txn'],
            'code': self._result['_code'],
            }

        return json.dumps(data) 

    ######################################################
    # Analysis and presentation 
    ######################################################

    def analyze_xmls(self): 
        """
        Analyze the XML being sent to the server
        """ 
        
        pid_content_sizes = \
            self._checker.analyze(xml=self._result['_request_unsigned_xml'],
                            is_file=False) 
        signed_content_sizes = \
            self._checker.analyze(xml=self._result['_request_signed_xml'],
                            is_file=False) 
        self._stats['_pid_content_sizes'] = pid_content_sizes
        self._stats['_signed_content_sizes'] = signed_content_sizes

    def humanize_basic(self, req): 
        """
        Generate a readable string out of request. Simple version. It
        will not work for complicated queries. It is coming down the
        line.
        """
        
        # XXX Pg 12 of the API gives a full XML. We have to turn the
        # corresponding request structure in something readable. Right
        # now this function code supports only a subset of attributes.

        msg = "" 
        try: 
            if "Pi" in req['demographics']: 
                pi = req['Pi']
                if (pi['ms'] == "E"): 
                    msg = msg + "Exact(name)" #% (pi['name'])
                else:
                    msg = msg + "Partial(name)" #% (pi['name'])
        except:
            pass 

        try: 
            if "Pa" in req['demographics']: 
                pa = req['Pa']
                if (pa['ms'] == "E"): 
                    msg = msg + "Exact(address)" #% (pa['street'])
                else:
                    msg = msg + "Partial(addresses)" #% (pa['address'])
        except:
            pass 
        
        try: 
            if "FMR" in req['biometrics']: 
                msg = msg + "(Finger Prints)" 
        except:
            pass 

        return "(%s,%s) " %(req['uid'], msg)
    
    def print_stats(self): 
        """
        The call in numbers 
        """
        log.debug("Auth server latency: %0.3f secs" % (self._stats['_auth_call_latency']))
        log.debug("Payload (Pid) Element:")
        log.debug(self._stats['_pid_content_sizes'])
        log.debug("Fully Signed XML:")
        log.debug(self._stats['_signed_content_sizes'])

    ######################################################
    # Core functions 
    ######################################################

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

        # Now cleanup 
        if (self._cfg.request.xmlcleanup is True): 
            os.unlink(tmpfp_unsigned) 
            os.unlink(tmpfp_signed)
        
        return signed_content 
    
    def generate_signed_xml(self): 
        """ 
        Update the attribute and generate the signed xml 
        """ 
        cfg = self._cfg

        # Initialization
        self.set_txn()

        try: 
            client_xml = self._result['_request_client_xml']
        except: 
            raise("Non-existing client XML to process") 
            
        # Update elements
        obj = objectify.fromstring(client_xml)
        obj.set('lk', self._cfg.common.license_key) 
        obj.set('txn', self._txn) 
        obj.set('uid', self._uid) 
        obj.set('sa', self._sa) 
        obj.set('ac', self._ac) 
        
        self._result['_request_unsigned_xml'] = \
                 etree.tostring(obj, pretty_print=False)

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
            res = self._checker.extract(xml=self._result['_request_unsigned_xml'],
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
        
        return True 

    def execute(self, generate_xml=True): 
        """
        Execute the query specified in the configuration file. 
        If necessary generate the signed XML from the client XML 
        """
        
        cfg = self._cfg 

        if generate_xml: 
            self.generate_signed_xml() 

        # Testing will use the local cert instead of UIDAI's public
        # cert for encryption. Therefore will fail the tests at the
        # authentication server.
        
        if (cfg.common.mode != "testing"):
            log.debug("Connecting to the server...") 
            conn = AuthConnection(cfg, ac=cfg.common.ac)
            try: 
                [auth_call_latency, xml] = \
                    conn.authenticate(uid=cfg.request.uid, 
                                      data=self._result['_request_signed_xml']) 
                    
                self._stats['_auth_call_latency'] = auth_call_latency
            except: 
                traceback.print_exc(file=sys.stdout)
                raise Exception("Unable to complete authentication")
                
            log.debug("Response from Auth Server")
            log.debug(xml)

            res = AuthResponse(cfg=cfg, 
                               uid=cfg.request.uid)

            res.load_string(xml)
            self._result['_latency'] = self._stats['_auth_call_latency']
            self._result['_xml']   = xml 
            self._result['_ret']   = res.get_ret()
            self._result['_err']   = res.get_err()
            self._result['_ts']    = res.get_ts() 
            self._result['_info']  = res.get_info() 
            self._result['_txn']   = res.get_txn() 
            self._result['_code']   = res.get_code() 
            
            self._result['_err_message'] = res.lookup_err()
            
            # XXX add a check for txnid 
            log.debug("Match result = %s " % res.get_ret())
            log.debug("Error = %s " % res.lookup_err())
            log.debug("Flags that are set: %s " % res.lookup_usage_bits())
            log.debug("UID Hash = %s " % res.get_uid_hash())
            log.debug("Request uid hash = %s " % self.get_uid_hash())            
            log.debug("Demo hash = %s " % res.get_demo_hash())
            log.debug("Request Demo hash = %s " % self.get_demo_hash())

            
            log.debug("[%0.3f secs] %s -> %s " % \
                (self._stats['_auth_call_latency'],
                 self.humanize_basic(self._cfg.request),
                 res.get_ret()))
                                         
            self.print_stats() 

        else:
            log.debug("Skipping contacting the server in the 'testing' mode")
            log.debug("Please change cfg >> common >> mode to enable server posting")

        
if __name__ == '__main__':

    cmd = AuthConfig("request", "Encapsulate and sign the XML") 
    cfg = cmd.update_config() 
    
    #=> Setup logging 
    logging.basicConfig(
	#filename=cfg.common.logfile, 
	format=cfg.common.logformat)

    logging.getLogger().setLevel(cfg.common.loglevel)
    log.info("Starting my AuthClient")

    if cfg.request.command == "generate": 

        # => Generate the XML file 
        data = AuthData(cfg=cfg) 
        data.generate_client_xml() 
        exported_jsoned_data = data.export_request_data() 

        # Sign and send it out...
        req = AuthRequest(cfg=cfg)
        req.import_request_data(exported_jsoned_data)
        req.execute() 
        
        if req.is_successful():
            log.debug("Authentication successful!")
 	else: 
            log.debug("Authentication unsuccessful!")
	    
        
        if cfg.common.mode != 'testing': 
            exported_jsoned_data = req.export_response_data() 
            data.import_response_data(exported_jsoned_data) 

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
    

