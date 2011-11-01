import sha, md5, os, sys
from M2Crypto import RSA, BIO, Rand, m2, EVP, X509, ASN1
from M2Crypto.ASN1 import ASN1_UTCTIME 
import base64 

class AuthCrypt():
    
    def __init__(self, pub_key, priv_key):
        self._public_key = pub_key
        self._private_key = priv_key
        return 
    
    def get_cert_expiry(self): 
        x509 = X509.load_cert(self._public_key)
        return x509.get_not_after().__str__()  

    # Returns encrypted and base64 encoded data
    def encrypt(self, data):
        if (data == None or data == ""):
            raise Exception("No data to encrypt") 
        
        x509 = X509.load_cert(self._public_key)
        rsa = x509.get_pubkey().get_rsa()
        enc_data=rsa.public_encrypt(data, RSA.pkcs1_padding)
        #res = enc_data.encode('base64') 
        res = base64.b64encode(enc_data)
        #print "\"%s\"" % (res)
        return res 
    
    # Decryption of data requires private key. Assumes the data is 
    # base64 encoded. 
    def decrypt(self, data):

        if (data == None or data == ""):
            raise Exception("No data to encrypt") 
        
        dec_data = base64.b64decode(data)
        rsa = RSA.load_key(self._private_key) 
        res = rsa.private_decrypt(dec_data, RSA.pkcs1_padding)
        #print "\"%s\"" % (res)
        return res 
    
    def test(self, show=True): 
        
        data = "39jsjsfdhdshfd" # some test data
        if show:
            print "Encryption payload: ", data
        enc_data = self.encrypt(data)
        if show:
            print "Encrypted base64 encoded data:" 
            print enc_data 
        dec_data = self.decrypt(enc_data)
        if show:
            print "Decrypted data" 
            print dec_data
        
        if (data != dec_data): 
            raise Exception("Encryption is not functioning correctly")
        else:
            if show:
                print "Encrytion payload and decrypted data matched" 
        return True 

if __name__ == '__main__':
    
    auth = AuthCrypt("fixtures/public.pem", "fixtures/public.pem") 
    print "certificate expiry = ", auth.get_cert_expiry()
    auth.test() 
