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

import sys
sys.path.append("lib") 

import libxml2
from lxml import etree, objectify 

import dumper 
import hashlib 
from config import Config 
import traceback 
import base64 
import random 
from datetime import datetime
from auth_crypt import AuthCrypt 
from M2Crypto import Rand 

class AuthRequest():

    """
    Base class to parse, validate, and generate auth requests going to
    the server. Mostly it will be used in the generate mode. The aim
    is to simplify writing applications around the auth request. We
    could potentially use this with AppEngine and Django that are
    python-based. This interface supports only v1.5 and public AuAs 
    """
    
    def __init__(self, cfg=None, biometrics=False, uid="", 
                 tid="", lk="", txn=""):
        
        self._cfg = cfg 
        self._biometrics = biometrics
        self._pidxml_biometrics = None
        self._pidxml_demographics = None 
        self._session_key = None

        self._tid = tid
        self._lk = lk
        self._ac = "public"
        self._ver = "1.5" 
        self._sa = "public" 
        self._uid = uid
        self._txn = txn 
        self._skey = { 
            '_ci': None, 
            '_text': None}
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

    def validate(self): 
        
        if ((self._skey['_ci'] == None) or (self._skey['_text'] == None)):
            raise Exception("Invalid Skey ci or text")
        
        if (self._pidxml_demographics == None and 
            self._pidxml_biometrics == None):
            raise Exception("Payload (demographics/biometics) not set") 

    def xsd_check(self, xml_text=None):
        
        if xml_text == None: 
            xml_text = self.tostring() 
        
        f = file(cfg.xsd.request)
        schema = etree.XMLSchema(file=f)
        parser = objectify.makeparser(schema = schema)
        try: 
            obj = objectify.fromstring(xml_text, parser)
            print "The XML generated is XSD compliant" 
        except: 
            print "[Error] Unable to parse incoming message" 
            traceback.print_exc(file=sys.stdout) 
            return None 
        return obj

    def set_skey(self):
        
        a = AuthCrypt(cfg.request.uid_cert_path, None) 
        when = a.get_cert_expiry() #Jun 28 04:40:44 2012 GMT
        expiry = datetime.strptime(when, "%b %d %H:%M:%S %Y %Z")
        self._session_key = Rand.rand_bytes(self._cfg.common.rsa_key_len) 
        print "session_key = ", self._session_key 
        self._skey['_ci'] = expiry.strftime("%Y%M%d")
        self._skey['_text'] = a.encrypt(self._session_key)

    def get_skey(self):
        return { 
            'ci': self._skey['_ci'],
            'text': self._skey['_text'],
            }

    def set_data(self, data=""):
        self._data = data 
        
    def get_data(self):
        self._data 

    def generate_xmldsig_template(self):
        "" 
        
    def set_hmac(self): 
        key = self._cfg.request.hmac_key 
        ""
        
    def set_pidxml_biometrics(self, datatype="FMR", data=None, ts=None):
        
        if (datatype != "FMR"): 
            raise Exception("Non FMR biometrics not supported") 
        
        if (data == None): 
            raise Exception("Data for biometrics inclusion is missing") 

        self._uses['_bio'] = "y"
        self._uses['_bt'] = "FMR"

        if ts == None:
            ts = Datetime.utcnow() 
        root = etree.Element('Pid', 
                             xmlns="http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0",
                             ts=ts.strftime("%Y-%m-%dT%H:%M:%S"),
                             ver="1.0")
        bios = etree.SubElement(root, "Bios")
        bio=etree.SubElement(bios, "Bio", type="FMR")
        bio.text = data 
        doc = etree.ElementTree(root) 
        self._pidxml_biometrics = etree.tostring(doc,pretty_print=True)

    def set_pidxml_demographics(self, datatype="Name", data=None, ts=None):
        
        if (datatype != "Name" or data == None):
            raise Exception("Does not support demographic checks other than Name") 
        
        self._uses['_pi'] = "y" 
        
        if ts == None:
            ts = datetime.utcnow() 

        root = etree.Element('Pid', 
                             xmlns="http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0",
                             ts=ts.strftime("%Y-%m-%dT%H:%M:%S"),
                             ver="1.0")
        demo = etree.SubElement(root, "Demo")
        pi=etree.SubElement(demo, "Pi", ms="E", name=data)
        doc = etree.ElementTree(root) 
        self._pidxml_demographics = etree.tostring(doc,pretty_print=True)

    def tostring(self):

        self.validate()

        root = etree.Element('Auth', 
                                xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0",
                                ver=self._ver,
                                tid=self._tid, 
                                ac=self._ac, 
                                sa=self._sa,
                                txn = self._txn,
                                uid = self._uid,
                                )
        skey = etree.SubElement(root, "Skey", ci=self._skey['_ci'])
        skey.text = base64.b64encode(self._skey['_text'])
        
        uses = etree.SubElement(root, "Uses", 
                                otp=self._uses['_otp'],
                                pin=self._uses['_pin'],
                                bio=self._uses['_bio'],
                                pfa=self._uses['_pfa'],
                                pi=self._uses['_pi'],
                                pa=self._uses['_pa'])
        
        data = etree.SubElement(root, "Data")
        data.text = base64.b64encode(self._data)

        doc = etree.ElementTree(root) 
        return ("<?xml version=\"1.0\"?>\n%s" %(etree.tostring(doc, pretty_print=True)))

    def load(self, xmlfile):        
        xml_text = file(xmlfile).read() 
        o = self.xsd_check(xml_text) 
        
if __name__ == '__main__':
    
    cfg = Config('auth.cfg') 
    x = AuthRequest(cfg, uid="123412341234", lk=cfg.common.license_key)
    x.set_skey() 
    x.set_pidxml_demographics(data="KKKK")
    x.set_data("dfdsfdfds") 
    s = x.tostring() 
    print s 
    x.xsd_check()

    test_xml = file('fixtures/authrequest.xml').read() 
    print "Validating this incoming XML" 
    print test_xml
    x.xsd_check(test_xml) 
    
