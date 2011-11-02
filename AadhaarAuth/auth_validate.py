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

"""
Validation routines for Auth XML files generated and received. 
"""
import sys
sys.path.append('lib') 
import dumper 

from lxml import etree, objectify 
from config import Config
import traceback 

class AuthValidate(): 
    
    def __init__(self, request_xsd, testing=True): 
        self._testing = testing
        self._request_xsd = request_xsd 
        return 

    def xsd_check_memory(self, xml_text):
        """
        Check for whether the XML generated is compliant with the XSD
        or not. Eventually this will be moved out into a separate
        class and corresponding binary.
        """
        f = file(self._request_xsd)
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

    def xsd_check_file(self, xmlfile):        
        """
        XSD-validate an xml file generated externally.
        """
        xml_text = file(xmlfile).read() 
        return self.xsd_check_memory(xml_text) 
    
    def check_dom(self, obj):

        if obj == None: 
            return False
        
        result = True 
        
        #print objectify.dump(obj) 

        # => Root element
        # UID present 
        
        #<Auth txn="" ac="public"
        #xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0"
        #ver="1.5" uid="123412341234" tid="public" sa="public">
        
        uid = obj.get('uid')
        if (uid == None or len(uid) != 12):
            print "UID attribute is either missing or has incorrect length",\
                "Please check the UID attribute" 
            result = False

        # Indirect way of checking namespace 
        tag = obj.tag 
        tag_default="{http://www.uidai.gov.in/authentication/uid-auth-request/1.0}Auth"
        if (tag == None or tag != tag_default):
            print "xmlns is missing or is incorrect"
            print "xmlns = ", tag
            result = False 
        
        tid = obj.get('tid')
        if (tid == None):
            print "tid is missing" 
            result = False 
            if (self._testing): 
                if (tid != "public"): 
                    print "tid should be set to 'public' during testing" 
                    result = False 

        sa = obj.get('sa')
        ac = obj.get('ac')
        if (ac == None or sa == None):
            print "sa or ac is missing" 
            result = False 
        if (self._testing): 
            if (ac != "public" or sa != "public"):
                print "tid and sa should be set to public during testing" 
                result = False

        ver = obj.get('ver')
        if (ver != "1.5"):
            print "Attribute 'ver' should be set to 1.5"
            result = False 
        
        # => Skey element checks         
        #<Skey ci="20150922">YlZUdW9kek4yb3UrZ1dNL1ZqeDJmRlBIbHhSVTRwVjd4TkdRVGVGWmJ2eTV0WnQwbUZpYWFzRURyTWdXaXFkdU05Nm4zMXNxenVqR0phZTZvUDVJTXE3ZkVPRzBNemNBdThwWm1XbW9HMjkydCs2cFJkR0FobWVaSFVpZzBSQVFiS1ZVL3pnVDhocXp6d2xLNWljTTB0STNMSE1LT3paU3V1VmNVbGxKbTZ2SlF3aUZTUWwzWFRVQW51SGdaeXRMTHN0RkRCZXo2U0laRmNBckxRQytEL2xWWlhPdGE4RUIwMGdyVmtpZUc1aE8xVzlaemdTa295SC96dC9ic0trSXdZdTZhMGE2N25wQng1V0hWMGdsbnpZQkRlOE1CTkduWm9TWGE0RUdya0xLNnZTdlVFaEU5WnRKMDdJSkxUS3lsUTFFV3U4YVFXQnd6UEdsVk4vM2x3PT0=</Skey>

        # Check for uidai's cert expiry date
        expiry = obj["Skey"].get('ci')
        if ((self._testing == True) and (expiry != "20150922")):
            print "Expiry date is wrong! Check the UIDAI ", \
                  "certificate being used" 
            result = False
            
        enc_session_key = obj["Skey"].text
        session_key_len = len(enc_session_key)
        print session_key_len 
        if (enc_session_key == None or session_key_len != 460):
            print "Encrypted/encoded session key length is wrong.", \
                  "Please check the session key"             
            result = False 
        
        #<Uses pfa="n" bio="n" pin="n" pa="n" otp="n" pi="y"/>
        for attrib in ['pfa', 'bio', 'pin', 'pa', 'otp', 'pi']:
            attrib_val = obj["Uses"].get(attrib)
            if ((attrib_val != None) and 
                (attrib_val != "y") and (attrib_val != "n")):
                print "Invalid attribute %s of Uses element." % (attrib)
                result = False

        pi = obj["Uses"].get('pi')
        bio = obj["Uses"].get('bio')
        if ((pi == None and bio == None) or 
            (pi == "y" and bio == "y")):
            print "pi and bio attributes are mutually exclusive"
            result = False 
        
        

        if result == False:
            print "XML is compliant but invalid" 
        else:
            print "XML is compliant and probably valid" 
        return result
        
    def validate(self, xml,is_file=True): 

        if is_file: 
            obj = self.xsd_check_file(xml)
        else:
            obj = self.xsd_check_memory(xml)
        
        if obj == None:
            return False 
        
        return self.check_dom(obj)
        
        
if __name__ == '__main__':
    
    cfg = Config('fixtures/auth.cfg') 
    v = AuthValidate(cfg.xsd.request) 
    print "Validating Auth Request XML" 
    #v.xsd_check_file('fixtures/authrequest.xml')
    v.validate('fixtures/authrequest.xml')
