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

import os, os.path, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/lib")

from lxml import etree, objectify 

import logging 
import dumper 
import hashlib 
from config import Config 
import traceback 
import base64 
from datetime import * 
import hashlib 
import binascii 

from command import AuthConfig

log = logging.getLogger("AuthResponse") 

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

    
    # XXX Remove all these parameters. Only include the _response 
    # object They are not being used anyway. 
    def __init__(self, cfg=None, uid=None, ret="n", txn="", 
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
        self._uid = uid 

    def lookup_err(self): 
        
        # 
        errors = { 
            '100': "'Pi' (basic) attributes of demographic data did not match.",
            '200': "'Pa' (address) attributes of demographic data did not match",
            '300': "Biometric data did not match",
            '500': "Invalid encryption",
            '500': "Invalid encryption of Skey",
            #This error will be returned if Auth server is not able to
            #decrypt the "Skey" value.  In such cases, please review
            #your RSA encryption code.  Also, ensure that you are
            #using correct certificate.
 
            '501': "Invalid certificate identifier (ci)",
            #(Refer "ci" attribute of Skey).  In such cases, please
            #ensure that you are deriving this value from the
            #certificate that was used for encryption.  Do not
            #hardcode this value in your application, instead always
            #derive its value from the Certificate, which contains its
            #own expiry date.
 
            '502': "Invalid Pid encryption",             
            #This error will be returned if Auth server is not able to
            #decrypt the <Data> element.  In such cases, please review
            #your AES encryption code, and also ensure that AES key
            #that was used for Pid encryption was indeed encrypted to
            #create Skey. Please make sure that you use same AES key
            #for encrypting both Pid and Hmac.
 
            '503': "Invalid Hmac encryption", 
            #This error will be returned if Auth server is not able to
            #decrypt the <Hmac> element.  In such cases, please review
            #your AES encryption code, and also ensure that AES key
            #that was used for Hmac encryption was indeed encrypted to
            #create Skey.  Please make sure that you use same AES key
            #for encrypting both Pid and Hmac.

            '510': "Invalid Auth XML format",
            '511': "Invalid PID XML format",
            '520': "Invalid device",
            '530': "Invalid authenticator code",
            '540': "Invalid version",
            '550': "Invalid 'Uses' element attributes",
            '561': "Request expired ('Pid->ts' value is older than N hours where N is a configured threshold in authentication server)",
            '562': "Timestamp value is future time (value specified 'Pid->ts' is ahead of authentication server time beyond acceptable threshold)",
            '563': "Duplicate request (this error occurs when exactly same authentication request was re-sent by AUA)",
            '564': "HMAC Validation failed",
            '565': "License key has expired",
            '566': "Invalid license key",
            '567': "Invalid input (this error occurs when some unsupported characters were found in Indian language values, 'lname' or 'lav')",
            '568': "Unsupported Language",
            '569': "Digital signature verification failed (this means that authentication request XML was modified after it was signed)",
            '570': "Invalid key info in digital signature (this means that certificate, used for signing the authentication request is not valid - it is either expired, or does not belong to the AUA or is not created by a well-known (Certification Authority)",
            '571': "PIN Requires reset (this error will be returned if resident is using the default PIN which needs to be reset before usage)",
            '572': "Invalid biometric position (This error is returned if biometric position value - 'pos' attribute in 'Bio' element - is not applicable for a given biometric type - 'type' attribute in 'Bio' element.)",
            '573': "Pi usage not allowed as per license",
            '574': "Pa usage not allowed as per license",
            '575': "Pfa usage not allowed as per license",
            '576': "FMR usage not allowed as per license",
            '577': "FIR usage not allowed as per license",
            '578': "IIR usage not allowed as per license",
            '579': "OTP usage not allowed as per license",
            '580': "PIN usage not allowed as per license",
            '581': "Fuzzy matching usage not allowed as per license",
            '582': "Local language usage not allowed as per license",
            '700': "Invalid demographic data",
            '710': "Missing 'Pi' data as specified in 'Uses'",
            '720': "Missing 'Pa' data as specified in 'Uses'",
            '721': "Missing 'Pfa' data as specified in 'Uses'",
            '730': "Missing PIN data as specified in 'Uses'",
            '740': "Missing OTP data as specified in 'Uses'",
            '800': "Invalid biometric data",
            '810': "Missing biometric data as specified in 'Uses'",
            '811': "Missing biometric data in CIDR for the given Aadhaar number",
            '820': "Missing or empty value for 'bt' attribute in 'Uses' element",
            '821': "Invalid value in the 'bt' attribute of 'Uses' element",
            '901': "No authentication data found in the request (this corresponds to a scenario wherein none of the auth data - Demo, Pv, or Bios - is present)",
            '902': "Invalid 'dob' value in the 'Pi' element (this corresponds to a scenarios wherein 'dob' attribute is not of the format 'YYYY' or 'YYYY-MM-DD', or the age of resident is not in valid range)",
            '910': "Invalid 'mv' value in the 'Pi' element",
            '911': "Invalid 'mv' value in the 'Pfa' element",
            '912': "Invalid 'ms' value",
            '913': "Both 'Pa' and 'Pfa' are present in the authentication request (Pa and Pfa are mutually exclusive)",
            '930': "Technical error that are internal to authentication server",
            '931': "Technical error that are internal to authentication server",
            '932': "Technical error that are internal to authentication server",
            '933': "Technical error that are internal to authentication server",
            '934': "Technical error that are internal to authentication server",
            '935': "Technical error that are internal to authentication server",
            '936': "Technical error that are internal to authentication server",
            '937': "Technical error that are internal to authentication server",
            '938': "Technical error that are internal to authentication server",
            '939': "Technical error that are internal to authentication server",
            '940': "Unauthorized ASA channel",
            '941': "Unspecified ASA channel",
            '980': "Unsupported option",
            '999': "Unknown error",
            }

        try:
            err = self._response['_err']
            res = errors[err]
            log.debug("Error lookup for %s: %s " % (err, res))
        except: 
            res = "No error"

        return res
        
    def lookup_usage_bits(self, what=None):
        
        def pos(digit, position):
            return ((digit * 4) - position)

        usage_positions = { 
            
            # 1st hexadecimal digit: Bit 3-0: Version number of
            # encoding. It will be hexadecimal "1" (binary: 0001, for
            # encoding specified in this document.
            
            'ver': pos(1,0),
            
            # 2nd hexadecimal digit
            'Pi->name':pos(2,3), 
            'Pi->lname':pos(2,2),
            'Pi->gender':pos(2,1),
            'Pi->dob':pos(2,0),
            
            # 3rd hexadecimal digit
            'Pi->phone':pos(3,3),
            'Pi->email':pos(3,2),
            'Pi->age':pos(3,2),
            'Pa->co':pos(3,1),
            
            # 4th hexadecimal digit
            'Pa->house':pos(4,3),
            'Pa->street':pos(4,2),
            'Pa->lm':pos(4,1),
            'Pa->loc':pos(4,0),
            
            # 5th hexadecimal digit
            'Pa->vtc':pos(5,3),
            'Pa->dist':pos(5,2),
            'Pa->state':pos(5,1),
            'Pa->pc':pos(5,0),
            
            # 6th hexadecimal digit
            'Pfa->av':pos(6,3),
            'Pfa->lav':pos(6,2),
            'FMR':pos(6,1),
            'FIR':pos(6,0), 
            
            # 7th hexadecimal digit
            'IIR':pos(7,3),
            'Pv->pin':pos(7,2),
            'Pv->otp':pos(7,1),
            'Tkn':pos(7,0),
            
            # 8th hexadecimal digit
            'Pa->po':pos(8,3),
            'Pa->subdist':pos(8,2),
            'Pi->dobt':pos(8,1),
            
            # Bit 0: Unused
            # 9th to 12th Hexadecimal digits
            # Currently unused. Will have value 0.
            }

        if (what != None): 
            try: 
                position = usage_positions[what]
                flag = self._response['_usage_data'][position-1]
                log.debug("Looked up flag %s - bit pos %d with result %s " \
                    % (what, position, flag))
            except: 
                raise Exception("Unknown flag to lookup in usage data") 

            return flag
        else:
            # return all the flags that are set
            res = []
            all_usages = usage_positions.keys() 
            for what in all_usages:
                position = usage_positions[what]
                flag = self._response['_usage_data'][position-1]
                #log.debug("Looked up flag %s - bit pos %d with result %s " \
                #    % (what, position, flag))
                if (flag == "1"):
                    res = res + [what]
            return res 

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
        return self._ts 
    
    def get_txn(self): 
        return self._txn 

    def get_info(self): 
        return self._info

    def xsd_check(self, xml_text,xsd):
        
        if xml_text == None: 
            xml_text = self.tostring() 
        
        f = file(xsd)
        schema = etree.XMLSchema(file=f)
        parser = objectify.makeparser(schema = schema)
        try: 
            obj = objectify.fromstring(xml_text, parser)
            log.debug("The XML generated is XSD compliant")
        except: 
            log.error("Unable to parse incoming message")
            log.error(traceback.print_exc(file=sys.stdout))
            return None
        return obj

    def generate_xmldsig_template(self):
        "" 
        
    def tostring(self):

        # The XML should be loaded into the _response object 
        # Process all the variables there alone
        raise Exception("Dont use this") 


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

    def load_string(self, xml):

        try: 
            obj = objectify.fromstring(xml.encode('utf-8'))
        except Exception as e:
            log.error("Could not parse xml: %s " % e.args)
            raise Exception("Could not parse the XML response") 
        
        #print type(obj)        
        #print obj.get('info')

        self._response = {
            '_info':  obj.get('info'), 
            '_err': obj.get('err'), 
            '_code': obj.get('code'),
            '_ret': obj.get('ret'),
            '_ts': obj.get('ts'),
            '_txn': obj.get('txn')
            }
        self._response['_ver'] = self._response['_info'][0:2]
        self._response['_uid_hash'] = self._response['_info'][2:66]
        self._response['_demo_hash'] = self._response['_info'][66:130]

        # => Turn the hex info into a flag 
        def hextobin(s):
            bin_data = ""
            for i in range(0,len(s)):
                h=s[i]
                bin_data = bin_data + bin(int(h, 16))[2:].zfill(4)
            return bin_data 
        usage_data =self._response['_info'][130:142]
        self._response['_usage_data'] = hextobin(usage_data)
        return 
    
    def get_ts(self): 
        return self._response['_ts'] 

    def get_txn(self): 
        return self._response['_txn'] 

    def get_code(self): 
        return self._response['_code'] 

    def get_ts(self): 
        return self._response['_ts'] 
    
    def get_uid_hash(self):
        return self._response['_uid_hash'] 

    def get_demo_hash(self):
        return self._response['_demo_hash'] 

    def get_ret(self):
        return self._response['_ret'] 

if __name__ == '__main__':

    cmd = AuthConfig("response", 
                     "Process the response from the auth server")
    cfg = cmd.update_config() 

    logging.getLogger().setLevel(cfg.common.loglevel)
    logging.basicConfig(filename=cfg.common.logfile,
                        format=cfg.common.logformat) 

    if (cfg.response.command == "generate"):
        response = AuthResponse(cfg, err=100, ts=datetime.utcnow())
        response.validate() 
        xml = response.tostring() 
        log.debug("XML generated = ")
        response.xsd_check(xml, cfg.common.response_xsd)
    elif (cfg.response.command == "validate"): 
        response = AuthResponse(cfg=cfg)
        test_xml = file(cfg.response.xml).read() 
        log.debug("Validating this incoming XML")
        log.debug(test_xml)

        #sig = AuthSignature() 
        #sig.verify_file(cfg.response.xml, cfg.common.uid_cert_path)

        #response.xsd_check(test_xml, cfg.common.response_xsd) 
        response.load_string(test_xml) 
        if (response.get_err()): 
            response.lookup_err()
        else:
            log.debug("Successful response")

        log.debug("Flags that are set: %s " % response.lookup_usage_bits())
        
    else:
        log.debug("Unknown command %s " % cfg.response.command)
        sys.exit(1) 
        
