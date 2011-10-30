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

from lxml import etree, objectify 

import dumper 
import hashlib 
from config import Config 
import traceback 
import base64 

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
            '_pi': "y",
            '_pa': "n",
            }
        self._hmac = ""
        self._data = ""

    def validate(self): 
        
        if ((self._skey['_ci'] == None) or (self._skey['_text'] == None)):
            raise Exception("Invalid Skey ci or text")
    
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

    def set_skey(self, ci="", text=""):
        self._skey['_ci'] = ci
        self._skey['_text'] = text

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
    x = AuthRequest(cfg, uid="123412341234")
    x.set_skey("23233", "ehhsks")
    x.set_data("dfdsfdfds") 
    s = x.tostring() 
    print s 
    x.xsd_check()

    test_xml = file('fixtures/authrequest.xml').read() 
    print "Validating this incoming XML" 
    print test_xml
    x.xsd_check(test_xml) 
    
