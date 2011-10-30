import sys
sys.path.append("lib") 

from lxml import etree, objectify 

import dumper 
import hashlib 
from config import Config 
import traceback 
import base64 
from datetime import * 


#<AuthRes ret="n" code="" txn="" err="" info="" ts="">
#</AuthRes>

class AuthResponse():

    """
    Base class to parse, validate, and generate auth requests going to
    the server. Mostly it will be used in the generate mode. The aim
    is to simplify writing applications around the auth request. We
    could potentially use this with AppEngine and Django that are
    python-based. This interface supports only v1.5 and public AuAs 
    """

    def __init__(self, cfg=None, ret="n", txn="", 
                 err=-1, info="", ts=datetime.utcnow(), 
                 code=-1):
        
        self._cfg = cfg 
        self._ret = ret 
        self._ts = ts
        self._txn = txn
        self._info = info
        # Check for the type of ts 
        self._ts = ts
        self._code = code 
        self._err = err 

    def validate(self): 
        
        if (self._err < 100 or self._err > 1000):
            raise Exception("Invalid err value") 

        #now = datetime.datetime.utcnow() 
        #if (datetime.timedelta(self._ts, now) > cfg.response.max_delay):
        #    raise Exception("Response too old?") 

        return True 

    def set_err(self, value): 
        self._err = value
    def get_err(self):
        return self._err 

    def set_ts(self, value): 
        # check for the type 
        self._ts = value
    def get_ts(self):
        self._ts 

    def xsd_check(self, xml_text=None):
        
        if xml_text == None: 
            xml_text = self.tostring() 

        f = file(cfg.xsd.response)
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

    def generate_xmldsig_template(self):
        "" 
        
    def tostring(self):

        self.validate()

        root = etree.Element('AuthRes', 
                             xmlns="http://www.uidai.gov.in/authentication/uid-auth-response/1.0",
                             ret=self._ret,
                             code=unicode(self._code),
                             # Generate in xs:Datetime format 
                             ts=self._ts.strftime("%Y-%m-%dT%H:%M:%S"),
                             info=self._info,
                             txn=self._txn,
                             err=unicode(self._err)
                             )

        doc = etree.ElementTree(root) 
        return ("<?xml version=\"1.0\"?>\n%s" %(etree.tostring(doc, pretty_print=True)))

    def load(self, xmlfile):        
        xml_text = file(xmlfile).read() 
        o = self.xsd_check(xml_text) 
        
if __name__ == '__main__':
    
    cfg = Config('auth.cfg') 
    x = AuthResponse(cfg, err=100, ts=datetime.utcnow())
    x.validate() 
    s = x.tostring() 
    print s 
    x.xsd_check()

    test_xml = file('fixtures/authresponse.xml').read() 
    print "Validating this incoming XML" 
    print test_xml
    x.xsd_check(test_xml) 
