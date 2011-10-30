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
#            ... gzGfV+qTcU+1lhQscYnwJqqFmoViZO7NRVwPcfgadXs=</SignatureValue> 
#            <KeyInfo> 
#                  <X509Data> 
#                        <X509Certificate>MIICfzCCAeigAwIBAgIGAbAh09VkMA0GCSqGSIb3DQEBBQUAMHoxCzAJBgNVBAYT 
#                        ...
#                              /upJnBH02TRb1Wq63OtcuyBIFA==</X509Certificate> 
#                        <X509SubjectName>CN=Public AUA,OU=Public,O=Public 
#                              AUA,L=Bangalore,ST=KA,C=IN</X509SubjectName> 
#                  </X509Data> 
#            </KeyInfo> 
#      </Signature> 
#</Auth> 
#

import sys
sys.path.append("lib") 

from lxml import etree 
import dumper 
import hashlib 
from config import Config 

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
            '_pi': "y"
            }
        self._hmac = ""
        self._data = ""
        self._signature_template = {
            'xmlns': 'http://www.w3.org/2000/09/xmldsig#',
            'canonicalizationmethod': "http://www.w3.org/2001/10/xml-exc-c14n#",
            'signaturemethod': "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            'transforms': [ "http://www.w3.org/2000/09/xmldsig#enveloped-signature" ],
            'digestmethod': "http://www.w3.org/2000/09/xmldsig#sha1"
            }

    def validate(self): 
        
        if ((self._skey['_ci'] == None) or (self._skey['_text'] == None)):
            raise Exception("Invalid Skey ci or text")
        

    def set_skey(self, ci="", text=""):
        self._skey['_ci'] = ci
        self._skey['_text'] = text

    def get_skey(self):
        return { 
            'ci': self._skey['_ci'],
            'text': self._skey['_text'],
            }
        
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
                                txn = self._txn
                                )
        skey = etree.SubElement(root, "Skey", ci=self._skey['_ci'])
        skey.text = self._skey['_text']

        doc = etree.ElementTree(root) 
        return etree.tostring(doc, pretty_print=True)

    def load(self, xmlfile):
        doc = etree.parse('authrequest.xml')
        
if __name__ == '__main__':
    
    cfg = Config('auth.cfg') 
    x = AuthRequest(cfg)
    x.set_skey("23233", "434344e4834ksfisjfkljfdslksdf") 
    print x.tostring() 

