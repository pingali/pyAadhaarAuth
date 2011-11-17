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
from command import AuthConfig 

log=logging.getLogger("AuthData")

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
class AuthData():

    """
    Base class to parse, validate, and generate auth requests going to
    the server. Mostly it will be used in the generate mode. The aim
    is to simplify writing applications around the auth request. We
    could potentially use this with AppEngine and Django that are
    python-based. This interface supports only v1.5 and public AuAs 
    """
    
    
    def __init__(self, cfg=None, uid="", tid="", txn=""):
        """
        Constructor of AuthData (see source for more details). 
        
        cfg: Config object (see fixtures/auth.cfg example) (default: None)
        uid: uid of the requestor (default="") 
        tid: terminal id (default: "public") 
        txn: transaction id (default: "") 

        """
        
        self._cfg = cfg 
        if (cfg.common.mode == 'testing'): 
            self._x509_cert = cfg.common.public_cert
        else: 
            self._x509_cert = cfg.common.uid_cert_path

        if (tid == None or tid == ""): 
            self._tid = cfg.common.tid
        else: 
            self._tid = tid

        self._ver = self._cfg.common.ver 

        if (uid == None or uid == ""): 
            self._uid = self._cfg.request.uid
        else: 
            self._uid = uid 

        self._txn = txn 
        
        # => internal state. XXX reduce this space 
        self._pidxml = None
        self._pidxml_biometrics = None
        self._pidxml_demographics = None 
        self._demo_hash = None        
        self._session_key = None
        
        #=> Session key 
        self._skey = { 
            '_ci': None, 
            '_text': None
            }
        
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
            '_bt': "FMR",
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
            '_request_client_xml': None, 
            }
        self._stats = {} 
        self._checker = AuthValidate(cfg=self._cfg, 
                                     request_xsd=self._cfg.common.request_xsd,
                                     testing=(self._cfg.common.mode == 'testing')) 

    ######################################################
    # Read and write internal state 
    ######################################################

    def get_uid_hash(self): 
        return hashlib.sha256(self._uid).hexdigest() 

    def get_demo_hash(self):
        return self._demo_hash

    def get_client_xml(self): 
        return self._result['_request_client_xml']

    def set_client_xml(self, xml): 
        self._result['_request_client_xml'] = xml 


    ######################################################
    # Checker routines
    ######################################################
    def validate(self): 
        """
        Check for whether the data is complete enough to be able to 
        generate an authentication request. 
        """
        
        # Max length of ac = 10 
        #if (self._ac == None or len(self._ac) > 10): 
        #    raise Exception("Invalid ac. " + 
        #                    "It is mandatory and maxlength is 10")

        if ((self._skey['_ci'] == None) or (self._skey['_text'] == None)):
            raise Exception("Invalid Skey ci or text")
        
        if (self._pidxml_demographics == None and 
            self._pidxml_biometrics == None):
            raise Exception("Payload (demographics/biometics) not set") 

    
    #######################################################
    # => Skey implementation
    #######################################################
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

    #######################################################
    # => Data element
    #######################################################
    def set_data(self, ts=None):
        """
        Set the content of the data element using the pidxml
        generated and stored as part of this class
        """
        
        if ts == None:
            ts = datetime.now() 
            
        # Create the pid element...
        pid = etree.Element('Pid', 
                             xmlns=self._cfg.common.data_xmlns,
                             ts=ts.strftime("%Y-%m-%dT%H:%M:%S"),
                             ver="1.0")

        
        # Add the demographic and biometric elements as appropriate 
        res_demo = self.set_pidxml_demographics(pid)
        res_bio = self.set_pidxml_biometrics(pid)
        if (res_demo == False and res_bio == False):
            log.error("Either Dmographic or biometric check must be enabled in the configuration")
            raise Exception("Invalid configuration") 
        
        # Add the PIN element.
        self.set_pidxml_pins(pid) 
        
        # XXX Todo 
        # self.set_meta(pid) 
        # self.set_location(pid) 

        #=> Extract the PID element 
        doc = etree.ElementTree(pid) 
        self._pidxml = etree.tostring(doc,pretty_print=False)
        log.debug("PidXML to be encrypted = %s" % self._pidxml)
        
        # Encrypt and encode the element and store it in the data 
        # attribute for future use 
        x = AuthCrypt(cfg=self._cfg) 
        encrypted_pid = x.aes_encrypt(key=self._session_key, msg=self._pidxml)
        self._data = base64.b64encode(encrypted_pid)
        log.debug("Data = %s " % self._data)
        return 

    def get_data(self):
        return self._data 

    #######################################################
    # => Hmac element
    #######################################################

    def set_hmac(self): 
        """
        Computes the hmac. It stores a base64 encoded AES encrypted hash
        """
        
        data = self._pidxml 

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

    #######################################################
    # => Generate Pid element 
    #######################################################    

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
    
    # => Handle Pin
    def set_pidxml_pins(self, pid): 
        """
        Add the Pin element to the XML 
        """
        try: 
            pv = self._cfg.request.pv
        except: 
            pv = None

        if pv == None:
            return False 
        
        try:
            otp = pv['otp']
        except: 
            otp = None 
            
        try: 
            pin = pv['pin']
        except: 
            pin = None 
        
        if (pin == None and otp == None): 
            log.error("""The request configuration should have complete Pv element or none. It should specify either or both of Pin and Otp""") 
            raise Exception("Invalid configuration")

        pv = etree.SubElement(pid, "Pv")
        if (pin != None):
            pv.set("pin", pin)
            self._uses['_pin'] = 'y'
        if (otp != None): 
            pv.set("otp", otp)
            self._uses['_otp'] = 'y' 

        return True 

    # => Handle biometrics 
    def set_pidxml_biometrics(self, pid, ts=None):
        """
        Generate the biometrics XML payload. Supports only FMR for now
        """ 
        try: 
            bio_attributes = self._cfg.request.biometrics
        except: 
            bio_attributes = [] 

        if len(bio_attributes) == 0: 
            return False 

        supported_attributes = ["FMR"] 
        overlap = [i for i in supported_attributes if i in bio_attributes]
        if len(overlap) == 0: 
            log.error("No valid attributes selected for biometric authentication")
            raise Exception("Invalid configuration") 

        bios = etree.SubElement(pid, "Bios")
        if "FMR" in overlap: 
            log.debug("FMR data = " + self._cfg.request['FMR']['bio'])
            try: 
                data = self._cfg.request['FMR']['bio']
            except:
                data = None

            if (data == None): 
                raise Exception("Data for biometrics inclusion is missing") 
 
            self._uses['_bio'] = "y"
            self._uses['_bt'] = "FMR"
            bio=etree.SubElement(bios, "Bio", type="FMR")
            bio.text = data

        doc = etree.ElementTree(bios) 
        self._pidxml_biometrics = etree.tostring(doc,pretty_print=False)
        return True 
    
    #=> Handle the demographics 
    def set_demo_attributes(self, demo, elem_name):
        """ 
        Extract the configuration data for various demographic
        elements and fill the demographic XML object. 
        
        demo: DOM object for Demo element
        elem_name: demographic element to be added (e.g., Pi, Pa, Pfa)
        """ 
        
        # What all is acceptable to the server? 
        all_attributes = { 
            "Pi":['ms', 'mv', 'name', 'lname', 'lmv', 'gender', 'dob', 
                  'dobt', 'age', 'phone', 'email'],
            "Pa":['ms','co','house','street','lm','loc', 'vtc',
                  'subdist','dist','state','pc','po'],
            "Pfa":['ms','mv','av','lav','lmv']
            }

        #=> Extract the element data from config 
        try: 
            # try looking for say cfg.request.Pi 
            elem_data = eval("self._cfg.request.%s" % elem_name)
        except:
            elem_data = None 

        if (elem_data == None): 
            return False 
        
        #=> See if there is an overlap 
        specified_attributes = elem_data.keys()
        valid_attributes = all_attributes[elem_name]
        attribute_overlap = [i for i in specified_attributes if i in valid_attributes]     
        log.debug("set_demo_attributes: specified = " + specified_attributes.__str__())
        log.debug("set_demo_attributes: overlap = " + attribute_overlap.__str__())
        # force addition of 'ms' attribute 
        if "ms" not in attribute_overlap: 
            attribute_overlap.append("ms")
            
        # make sure that there is more than one attribute that is
        # specified.
        if (len(attribute_overlap) == 1):
            log.error("No valid attributes selected for demographic authentication")
            raise Exception("Invalid configuration") 

        # For each of the acceptable attributes, insert them in 
        elem=etree.SubElement(demo, elem_name)
        for attrib in attribute_overlap:
            try: 
                attrib_val = eval('self._cfg.request[\'%s\'][\'%s\']' % (elem_name, attrib))
            except: 
                log.error("Configuration file requires request.%s.%s to be specified" % (elem_name, attrib))
                raise Exception("Invalid configuration")
            elem.set(attrib, attrib_val)
        return True 

    # => Set the demographics element 
    def set_pidxml_demographics(self, pid, ts=None):
        """ 
        Generate the demographics XML payload. Use the
        set_demo_attributes for each of the specified attributes.
        """
        try : 
            demo_attributes = self._cfg.request.demographics
        except: 
            demo_attributes = [] 
            
        if len(demo_attributes) == 0: 
            return False 

        # XXX This is always necessary to compute the demo hash in the
        # response. We dont do this for bios. Not sure what will
        # happen if an empty demo is sent or if the demo element does
        # not exist.

        # Not included by default unless explicitly configured by 
        # user
        demo = None 

        # 
        supported_attributes = ["Pi", "Pa", "Pfa"] 
        overlap = [i for i in supported_attributes if i in demo_attributes]
        if len(overlap) > 0: 
            demo = etree.SubElement(pid, "Demo")
            
            # set_demo_attributes has sideeffect of updating the 
            # demo object 
            if "Pi" in demo_attributes:
                if (self.set_demo_attributes(demo, "Pi")):
                    self._uses['_pi'] = "y" 
            if "Pa" in demo_attributes:
                if (self.set_demo_attributes(demo, "Pa")):
                    self._uses['_pa'] = "y" 
            if "Pfa" in demo_attributes:
                if (self.set_demo_attributes(demo, "Pfa")):
                    self._uses['_pfa'] = "y" 
                    
            # Extract the demographics component of the XML
            doc = etree.ElementTree(demo) 
        
            # update the internal state 
            self._pidxml_demographics = etree.tostring(doc,pretty_print=False)
            log.debug("Pid XML = %s " % self._pidxml_demographics)
        else: 
            log.debug("Pid XML = ''. No demo element defined")
            self._pidxml_demographics = "" 
            self._demo_hash = "".rjust(64, "0")
            return

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
    
    ######################################################
    # Export request data and import response data
    ######################################################
    
    def export_request_data(self): 
        """
        Export data to the sent to the AUA server. This could 
        be potentially encrypted using the cert given by the 
        AUA. Thats a feature of the next version 
        """
        data = {
            'uid': self._uid,
            'demo_hash': self._demo_hash, 
            'unsigned_xml': self._result['_request_client_xml'] 
            }
        return json.dumps(data) 

    def import_response_data(self,jsoned_data): 
        """
        Import data from the server
        """
        data = json.loads(jsoned_data) 
        
        log.debug("Received data from AUA: %s" % data)

        self._result['_err'] = data['err']
        self._result['_ret'] = data['ret']
        self._result['_err_message'] = data['err_message'] 
        return True 

    ######################################################
    # XML generation 
    ######################################################

    def tostring(self):
        """
        Write out the XML after some validation 
        """
        self.validate()
        
        # Elements ac, sa, txn, lk will set by the AUA. They are not
        # required for computing hmac and they are not encrypted. 
        root = etree.Element('Auth', 
                             xmlns=self._cfg.common.request_xmlns,
                             ver=self._ver,
                             tid=self._tid, 
                             ac="", #self._ac, 
                             sa="", #self._sa,
                             txn="", #self._txn,
                             uid = self._uid,
                             lk='', #self._lk
                             )
        
        # XXX This is a placeholder. Will be populated down 
        # the line. 
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

        if self._uses['_bio'] == "y":
            uses.set('bt',self._uses['_bt'])
        
        data = etree.SubElement(root, "Data")
        data.text = self._data
        hmac = etree.SubElement(root, "Hmac")
        hmac.text = self._hmac

        doc = etree.ElementTree(root) 
        return ("<?xml version=\"1.0\"?>\n%s" %(etree.tostring(doc, pretty_print=False)))
    


    def generate_client_xml(self): 
        """
        Generate the body of the XML that will be written out by
        tostring()
        """ 
        # => Elements of the final XML 
        self.set_skey() 
        self.set_data()
        self.set_hmac() 

        # => Extract and store the result 
        self._result['_request_client_xml'] = self.tostring()  # dump it 

        log.debug("Unsigned XML:")
        log.debug(self._result['_request_client_xml'])
    
        # =>  Now validate the xml generated 
        res = self._checker.validate(self._result['_request_client_xml'], 
                               is_file=False, signed=False)
        if (res == False): 
            log.debug("Invalid XML generated")
        
        #=> In testing mode extract the XML to see if we can get back
        # the origin XML 
        if (self._cfg.common.mode == "testing"):
            res = self._checker.extract(xml=self._result['_request_client_xml'],
                                  is_file=False,
                                  key=self._cfg.common.private_key)


        
if __name__ == '__main__':
       
    cmd = AuthConfig("data", "Capture and generate XML") 
    cfg = cmd.update_config() 
    
    #=> Setup logging 
    logging.basicConfig(
	#filename=cfg.common.logfile, 
	format=cfg.common.logformat)

    logging.getLogger().setLevel(cfg.common.loglevel)
    log.info("Starting auth data")
    
    if cfg.request.command == "generate": 

        # => Generate the XML file 
        data = AuthData(cfg=cfg)
        data.generate_client_xml()
        log.debug("Exported data : " + \
                      json.loads(data.export_request_data()).__str__())

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
    
