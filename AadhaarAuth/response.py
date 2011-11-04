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

import sys
sys.path.append("lib") 

from lxml import etree, objectify 

import dumper 
import hashlib 
from config import Config 
import traceback 
import base64 
from datetime import * 

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"


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

    def xsd_check(self, xml_text,xsd):
        
        if xml_text == None: 
            xml_text = self.tostring() 
        
        f = file(xsd)
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

    #def load(self, xmlfile, xsdfile):
    #    xml_text = file(xmlfile).read() 
    #    o = self.xsd_check(xml_text, xsdfile) 
    
    
if __name__ == '__main__':
    assert(sys.argv)
    if len(sys.argv) < 2:
        print """
Error: command line should specify a config file.

Usage: validate.py <config-file>

$ cat example.cfg
common: { 
    response_xsd: 'xsd/uid-auth-response.xsd'   
}
response: { 
    command: "validate",
    xml: "fixtures/authresponse.xml'
}
"""    
    cfg = Config(sys.argv[1]) 
    if (cfg.response.command == "generate"):
        x = AuthResponse(cfg, err=100, ts=datetime.utcnow())
        x.validate() 
        xml = x.tostring() 
        print s 
        x.xsd_check(xml, cfg.common.response_xsd)
    elif (cfg.response.command == "validate"): 
        test_xml = file(cfg.response.xml).read() 
        print "Validating this incoming XML" 
        print test_xml
        x.xsd_check(test_xml, cfg.common.response_xsd) 
    else:
        print "Unknown command %s " % cfg.response.command
        sys.exit(1) 
        
