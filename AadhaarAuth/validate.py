#!/usr/bin/env python 

###################################################################
###### WAIT! WAIT! WAIT! WAIT! WAIT! WAIT! WAIT! WAIT! WAIT! ######
######                                                       ######
###### THIS IS FROM THE MASTER BRANCH AND ALWAYS UNDER FLUX. ######
###### PLEASE CHECK WITH AUTHOR FOR A STABLE VERSION ##############
###################################################################

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

import hashlib
from lxml import etree, objectify 
from config import Config
import traceback 
import base64 

from crypt import AuthCrypt 
from checksum import VerhoeffChecksum

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"

class AuthValidate(): 
    """
    Validate Auth XMLs 
    """
    def __init__(self, cfg=None, 
                 request_xsd=None, testing=True): 
        self._cfg = cfg 
        self._testing = testing
        self._request_xsd = request_xsd 
        return 
    
    def set_xsd(self, xsd):
        """
        Set the XSD file that will used for validation of the XML 
        """
        self._request_xsd = xsd
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
    

    def check_dom(self, obj, signed=False):
        """
        This is the main function. This goes through each of the XML
        elements and run whatever checks are possible. 
        """

        if obj == None: 
            return False
        
        result = True 
        
        
        #print objectify.dump(obj) 

        #################################################
        # => Auth element
        #################################################

        #<Auth txn="" ac="public"
        #xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0"
        #ver="1.5" uid="123412341234" tid="public" sa="public">
        
        uid = obj.get('uid')
        if (uid == None or len(uid) != 12):
            print "UID attribute is either missing or has incorrect length",\
                "Please check the UID attribute" 
            result = False
            
        # UID numbering scheme rules
        # uid[1]: 0 = reserved, 
        #         1 = entities 
        #         2-9 = valid for individuals 
        #
        # uid[12]: Verhoeff's checksum 
        c = VerhoeffChecksum() 
        if not c.validateVerhoeff(uid):
            print "Invalid UID. It  has failed integrity check" 
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

        #lk="MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=" 
        lk = obj.get('lk')
        lk_default="MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=" 
        if (lk == None):
            print "Attribute lk is missing"
            result = False 
        if (self._testing):
            if (lk != lk_default):
                print "lk should be set to 'MK...xQ=' during testing"
                result = False

        #################################################
        # => Skey
        #################################################

        #<Skey ci="20150922">YlZUdW9kek4yb3UrZ1dNL1ZqeDJmRlBIbHhSVTRwVjd4TkdRVGVGWmJ2eTV0WnQwbUZpYWFzRURyTWdXaXFkdU05Nm4zMXNxenVqR0phZTZvUDVJTXE3ZkVPRzBNemNBdThwWm1XbW9HMjkydCs2cFJkR0FobWVaSFVpZzBSQVFiS1ZVL3pnVDhocXp6d2xLNWljTTB0STNMSE1LT3paU3V1VmNVbGxKbTZ2SlF3aUZTUWwzWFRVQW51SGdaeXRMTHN0RkRCZXo2U0laRmNBckxRQytEL2xWWlhPdGE4RUIwMGdyVmtpZUc1aE8xVzlaemdTa295SC96dC9ic0trSXdZdTZhMGE2N25wQng1V0hWMGdsbnpZQkRlOE1CTkduWm9TWGE0RUdya0xLNnZTdlVFaEU5WnRKMDdJSkxUS3lsUTFFV3U4YVFXQnd6UEdsVk4vM2x3PT0=</Skey>

        # Check for uidai's cert expiry date
        expiry = obj["Skey"].get('ci')
        if ((self._testing == True) and (expiry != "20150922")):
            print "Expiry date is wrong! Check the UIDAI ", \
                "certificate being used" 
            result = False
            
            enc_session_key = obj["Skey"].text
            session_key_len = len(enc_session_key)
            session_key_len_default = 460 # How/Why?
            if (enc_session_key == None or 
                session_key_len != session_key_len_default):
                print "Encrypted/encoded session key length is wrong.", \
                    "Please check the session key"             
                print "Default value for session key length = %d" % (session_key_len_default)
                result = False 
                
        #################################################
        # => Uses
        #################################################

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

        #################################################
        # => Data and Hmac
        #################################################

        obj["Data"]  # raise an exception if this is not present
        obj["Hmac"]  # raise an exception if this is not present
        
        if result == False:
            print "Body of Auth XML is compliant but invalid" 
        else:
            print "Body of XML is compliant and probably valid" 

        if not signed:
            return result
        
        # Check the signature now..
        try:
            signature = obj["{http://www.w3.org/2000/09/xmldsig#}Signature"]
        except:
            print "Signature element is either missing or has invalid ",\
            "namespace string"
            print "Namespace string should be ",\
                "'http://www.w3.org/2000/09/xmldsig#'"
            return False

        #################################################
        # => SignedInfo
        #################################################
        signedinfo = signature.SignedInfo
        
        # => Canonicalization
        canonalg = signedinfo.CanonicalizationMethod.get("Algorithm")
        #canonalg_default = "http://www.w3.org/2001/10/xml-exc-c14n#"
        canonalg_default = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        if (canonalg != canonalg_default):
            print "CanonicalizationMethod algorithm is non-existent or invalid"
            print "The Algorithm should be ", canonalg_default
            result = False
         
        # => SignatureMethod
        sigmethodalg = signedinfo.SignatureMethod.get("Algorithm")
        sigmethodalg_default="http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        if (sigmethodalg != sigmethodalg_default):
            print "SignatureMethod algorithm is non-existent of invalid"
            print "The Algorithm should be ", sigmethodalg_default
            result = False            
  

        # => Transform
        reference = signedinfo.Reference
        transformalg = reference.Transforms.Transform.get("Algorithm")
        transformalg_default="http://www.w3.org/2000/09/xmldsig#enveloped-signature" 
        if (transformalg != transformalg_default):
            print "Transform has non-existent of invalid algorithm"
            print "The Algorithm should be ", transformalg_default
            result = False
        
        # => DigestMethod
        digestmethodalg = reference.DigestMethod.get("Algorithm")
        #digestmethodalg_default="http://www.w3.org/2000/09/xmldsig#sha1"
        digestmethodalg_default="http://www.w3.org/2001/04/xmlenc#sha256"
        if (digestmethodalg != digestmethodalg_default):
            print "DigestMethod has non-existent of invalid algorithm"
            print "The Algorithm should be ", digestmethodalg_default
            result = False
        
        # => DigestValue
        digestvalue = reference.DigestValue.text
        if (digestvalue == None):
            print "Digest value should be non-null"
            result = False

        # => SignatureValue
        sigvalue = signature.SignatureValue.text
        if (sigvalue == None):
            print "Signature value should be non-null"
            result = False


        #################################################
        # => KeyInfo
        #################################################
        try:
            keyinfo = signature.KeyInfo
        except:
            keyinfo=None
            print "KeyInfo element is missing"
            result = False

        if keyinfo != None:
            x509cert = keyinfo.X509Data.X509Certificate
            if x509cert.text == None:
                print "X509Certificate element is missing" 
                result = False

            if True: # XXX fix this...
                x509name = keyinfo.X509Data.X509SubjectName
                if x509name.text == None:
                    print "X509SubjectName element is missing" 
                    result = False 
            
                # => If testing mode, check the name in the certificate
                if (self._testing): 
                    # First turn this <X509SubjectName>CN=Public
                    # AUA,OU=Public,O=Public
                    # AUA,L=Bangalore,ST=KA,C=IN</X509SubjectName>
                    # into CN=Public AUA,OU=Public,O=Public
                    # AUA,L=Bangalore,ST=KA,C=IN

                    l = x509name.text.splitlines()
                    l = [x.lstrip() for x in l]
                    t = ''.join(l)
                    t_default = "CN=Public AUA,OU=Public,O=Public AUA,L=Bangalore,ST=KA,C=IN"
                    if (t != t_default):
                        print "X509SubjectName element body is inconsistent",\
                            "with that expected in testing mode. Please check",\
                            "the local certificate being used"
                        print "Expected: ", t_default
        
        if result == False:
            print "XML is compliant but invalid" 
        else:
            print "XML is compliant and probably valid" 
        return result

    #def xmlsec_check(self, xmlfile, certfile):
    #
    #    from authrequest_verify import AuthRequestVerify
    #    v = AuthRequestVerify(certfile)
    #    v.verify(xmlfile)
    
    def validate(self, xml,is_file=True, signed=False): 

        # XSD check will fail if signature is included
        if (not signed and self._request_xsd != None):
            if is_file: 
                obj = self.xsd_check_file(xml)
            else:
                obj = self.xsd_check_memory(xml)
                
            if obj == None:
                return False 
        
            return self.check_dom(obj,signed)

        else: 
            if is_file:
                xml_text = file(xml).read()
            else:
                xml_text = xml 
            obj = objectify.fromstring(xml_text)
            return self.check_dom(obj,signed)
        
    # Check the contents of the payload 
    def extract(self, xml, is_file, key):
        """
        Extractor of the XML content using private key
        """
        
        #=> First extract the dom 
        if is_file:
            xml_text = file(xml).read()
        else:
            xml_text = xml 
        obj = objectify.fromstring(xml_text)

        # Load the private key
        crypt = AuthCrypt(cfg=self._cfg, 
                          pub_key="", 
                          priv_key=key)
        
        # Extract the session key 
        encrypted_skey = obj.Skey.text 
        skey = crypt.x509_decrypt(encrypted_skey)
        print "Extracted skey (encoded) = ",  \
            base64.b64encode(skey)

        # Extract the data
        data = obj.Data.text 
        encrypted_pid = base64.b64decode(data) 
        
        #=> Decrypt the data
        decrypted_pid = crypt.aes_decrypt(skey, encrypted_pid)
        print "Extracted data" 
        print "\"%s\"" % decrypted_pid 
        
        #=> Decrypt the hmac 
        encoded_hmac = obj.Hmac.text 
        decoded_hmac = base64.b64decode(encoded_hmac) 
        payload_pid_hash = crypt.aes_decrypt(skey, decoded_hmac) 
        print "Processing hmac ", encoded_hmac 
        print "Sha256 hash contained in XML (b64 encoded) = ", \
            base64.b64encode(payload_pid_hash)

        #=> Compute the hmac now for the pid element
        computed_pid_hash = hashlib.sha256(decrypted_pid).digest() 
        print "Sha256 hash of extract Pid XML (b64 encoded)= ", \
            base64.b64encode(computed_pid_hash)

        #=> Check for consistency 
        if (payload_pid_hash != computed_pid_hash): 
            raise Exception("Pid Element's hash in the " + \
                            "payload and computed value do not match")
        else:
            print "Success! The hashes matched" 
        
        return True 

if __name__ == '__main__':
    
    assert(sys.argv)
    if len(sys.argv) < 2:
        print """
Error: command line should specify a config file.

Usage: validate.py <config-file>

$ cat example.cfg
# Configuration for the AuthXML validator
common: {
    request_xsd: 'xsd/uid-auth-request.xsd',
...
    private_key: 'fixtures/public_key.pem' # note: this is pvt key of public AUA
}
validate: {
    command: 'xml-only',
    xml: 'fixtures/authrequest-with-sig.xml',
    signed: True, 
}

$ cat example2.cfg 
# Configuration for the AuthXML validator
common: {...
}
validate: {
    command: 'extract',
    xml: 'fixtures/authrequest-with-sig.xml',
}

command options: 

      'xsd'
      This assumes unsigned xml and validates the xml against the XSD.
      In addition it does XML element-by-element content validation" 

      'xml-only' 
      The script only does XML element-by-element content validation
      This does not do any XSD validation 
      
      'extract' 
      Extract the session and payload (pid) data, and check for 
      integrity 

      'xml-with-signature' (not supported yet)
      This is 'xml-only' plus signature validation 
  
      'extract'
      Extract the contents using specified private key and show

"""
        exit(1)


    cfg = Config(sys.argv[1]) 
    
    checker=AuthValidate(cfg=cfg)

    if cfg.validate.command == 'xsd':
        checker.set_xsd(cfg.common.response_xsd)
        checker.validate(cfg.validate.xml, is_file=True, 
                         signed=cfg.validate.signed)
    elif cfg.validate.command == 'xml-only':
        checker.validate(cfg.validate.xml, is_file=True, 
                         signed=cfg.validate.signed)
    #elif cfg.validate.command == 'xml-with-signature':
    #    v.validate(xmlfile, is_file=True, signed=cfg.validate.signed)
    #    v.xmlsec_check(xmlfile, cfg.validate.cert)
    elif cfg.validate.command == 'extract':
        checker.extract(cfg.validate.xml, 
                        is_file=True, 
                        key=cfg.common.private_key)
    else:
        print "Unknown validate command: ", cfg.validate.command
        exit(1)


#
#========================================================
#================ Sample XML ====================
#========================================================
#<?xml version="1.0"?> 
#<Auth xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" 
#      ver="1.5" tid="public" ac="public" sa="public" 
#      lk="MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=" uid="999999990019" 
#      txn="GEO.11051880"> 
#      <Skey ci="20131003">Nc6DrZKFk1oQXxfgnFUl0mmtYYIPl0RGaFd2oINkpChU1++xdddMx6Dlbz6mEYs3 
#            IyzChGjRXN5/al9r0runFX8LspTfMchwpxaaDIOyIUguBoYmPUqJDqTQcwey6Ntc 
#            TJWFSgOvBg+omUkdbK/9GOQ5KWWrN+E0A9JN0IPU4IJqJZmsA6ETZlVoZteYtoMI 
#            Ucv53qmxNPOEmJ3s4BC3ppHRRWRFMUp/eW7DFJ33W+uInZB6yekKE0dz8fYeo03w 
#            2JUT1wlafL7aseb04nv5tNEbllHWafmbMpbv2pXKr+WPgytjrygt1LagGqF4a5Mr 
#            /UTNwsy4m/YwlkWN0QcYVw== 
#      </Skey> 
#      <Uses otp="n" pin="n" bio="n" pa="n" pfa="n" pi="y" /> 
#      <Data>YOn05vg5qMwElULpEmdiH0j6rM1XWcbQN0n+CFNQeazouCgjyPBH/a2SwbFgq/fF 
#            CYUm+the8gQyYC36VO49NLcNcD7WdMhweoiDYgJoCX/t87Kbq/ABoAetfX7OLAck 
#            /mHrTmw8tsfJgo4xGSzKZKr+pVn1O8dDHJjwgptySr7vp2Ntj6ogu6B905rsyTWw 
#            73iMgoILDHf5soM3Pvde+/XW5rJD9AIPQGhHnKirwkiAgNIhtWU6ttYg4t6gHHbZ 
#            0gVBwgjRzM3sDWKzK0EnmA== 
#      </Data> 
#      <Hmac>xy+JPoVN9dsWVm4YPZFwhVBKcUzzCTVvAxikT6BT5EcPgzX2JkLFDls+kLoNMpWe 
#      </Hmac> 
#      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"> 
#            <SignedInfo> 
#                  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /> 
#                  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /> 
#                  <Reference> 
#                        <Transforms> 
#                              <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /> 
#                        </Transforms> 
#                        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /> 
#                        <DigestValue>Idd9hQtO+YAR4bjfQpNxXQ/EvXc=</DigestValue> 
#                  </Reference> 
#            </SignedInfo> 
#            <SignatureValue>SyFAqzqtJ/VTWcR5cdxoIcsa7GMmgJo7X2Rtr+CVYZLaL2myg3HgaasaT7tPOa95 
#                  xYJwnwA/pl+S7ki+W/4Kq1nraV/wxArgE5hFTUFG8G/MOcuMy9Ajd1VPvuqMGvHA 
#                  gzGfV+qTcU+1lhQscYnwJqqFmoViZO7NRVwPcfgadXs=</SignatureValue> 
#            <KeyInfo> 
#                  <X509Data> 
#                        <X509Certificate>MIICfzCCAeigAwIBAgIGAbAh09VkMA0GCSqGSIb3DQEBBQUAMHoxCzAJBgNVBAYT 
#                              AklOMQswCQYDVQQIEwJLQTESMBAGA1UEBxMJQmFuZ2Fsb3JlMQ4wDAYDVQQKEwVV 
#                              SURBSTEeMBwGA1UECxMVQXV0aGVudGljYXRpb24gU2VydmVyMRowGAYDVQQDExFV 
#                              SURBSSBBdXRoIFNlcnZlcjAeFw0xMTA2MjgwNDQwNDRaFw0xMjA2MjgwNDQwNDRa 
#                              MGkxCzAJBgNVBAYTAklOMQswCQYDVQQIEwJLQTESMBAGA1UEBxMJQmFuZ2Fsb3Jl 
#                              MRMwEQYDVQQKEwpQdWJsaWMgQVVBMQ8wDQYDVQQLEwZQdWJsaWMxEzARBgNVBAMT 
#                              ClB1YmxpYyBBVUEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJBEgKhZZNmH 
#                              ejKTFaSg0Z/KN6kP98/FKpPkGTlkovJxa7KX0x74I++JhObM8SkRgCGR3DBK/YZB 
#                              o0ZCbvs9czTEoDA8CBMDSFLEP5z+Zi65hdNT9XQiaeN0sSY7N4cafsS/KH/LESbM 
#                              6I5OLvSGj10aQB8KDgwItvp/7xK6/Vu3AgMBAAGjITAfMB0GA1UdDgQWBBSd3qZJ 
#                              j5lPp+1zkJJCqyZoTLLWAzANBgkqhkiG9w0BAQUFAAOBgQBiGVbCITrygzpC+09u 
#                              R/l8w0hCInLusQMZeXgHcnxBGDSk1AQxKk5UfQmCwHNcRJMB5Zkj8+9n6T+/wx6D 
#                              tKDelktgIoo7w0EJ6MdVJ9Qzr5PJcYzX+ERgJEd/NNNVoPjFc2Al2odjToZdFN8+ 
#                              /upJnBH02TRb1Wq63OtcuyBIFA==</X509Certificate> 
#                        <X509SubjectName>CN=Public AUA,OU=Public,O=Public 
#                              AUA,L=Bangalore,ST=KA,C=IN</X509SubjectName> 
#                  </X509Data> 
#            </KeyInfo> 
#      </Signature> 
#</Auth> 
#
