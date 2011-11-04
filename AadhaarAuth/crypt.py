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

import os, sys, string
import hashlib 
from M2Crypto import RSA, BIO, Rand, m2, EVP, X509
import base64 
import random 
from config import Config 

class AuthCrypt():
    """
    Encryption/decryption functions required by the authentication
    classes. This should eventually move to 'lib' directory 
    """
    def __init__(self, cfg, pub_key=None, priv_key=None):
        self._cfg = cfg 
        if (self._cfg == None): 
            raise Exception("AuthCrypt requires a configuration file") 

        self._public_key = pub_key
        self._private_key = priv_key
        self._enc_alg = cfg.common.encryption_algorithm
        return 
    
    def x509_get_cert_expiry(self): 
        """
        Get UIDAI certificate expiry date 
        """
        x509 = X509.load_cert(self._public_key)
        return x509.get_not_after().__str__()  

    # Returns encrypted and base64 encoded data
    def x509_encrypt(self, data):
        """
        Encrypt using x509 public key (of UIDAI) 
        """
        if (data == None or data == ""):
            raise Exception("No data to encrypt") 
        
        print "x509 Encrypting using cert", self._public_key
        
        x509 = X509.load_cert(self._public_key)
        rsa = x509.get_pubkey().get_rsa()
        enc_data=rsa.public_encrypt(data, RSA.pkcs1_padding)
        #res = enc_data.encode('base64')  
        res = base64.b64encode(enc_data)
        print "Encrypted data: \"%s\"" % (res)
        return res 
    
    # Decryption of data requires private key. Assumes the data is 
    # base64 encoded. 
    def x509_decrypt(self, data):
        """
        Decrypt using private key (works only if the private key is
        set as well - so non UIDAI).
        """
        if (data == None or data == ""):
            raise Exception("No data to encrypt") 

        print "x509 Decrypting using cert", self._private_key
        print "Decrypting data: \"%s\"" % (data)

        dec_data = base64.b64decode(data)
        rsa = RSA.load_key(self._private_key) 
        res = rsa.private_decrypt(dec_data, RSA.pkcs1_padding)
        #print "\"%s\"" % (res)
        return res 
    
    def x509_test(self, show=True): 
        """
        Test whether x509 encryption and decryption are working as
        expected (works only with non-UIDAI cert/key pairs because we 
        dont have access UIDAI private key).
        """
        data = "39jsjsfdhdshfd" # some test data
        if show:
            print "Encryption payload: ", data
        enc_data = self.x509_encrypt(data)
        if show:
            print "Encrypted base64 encoded data:" 
            print enc_data 
        dec_data = self.x509_decrypt(enc_data)
        if show:
            print "Decrypted data" 
            print dec_data
        
        if (data != dec_data): 
            raise Exception("Encryption is not functioning correctly")
        else:
            if show:
                print "Encrytion payload and decrypted data matched" 
        return True 

    ENC=1         
    DEC=0         

    # Ack. Code from here. 
    # http://stackoverflow.com/questions/5003626/problem-with-m2cryptos-aes
    def aes_build_cipher(self, key, iv, op=ENC):             
        """
        Obtains a cipher from EVP 
        """
        return EVP.Cipher(alg=self._enc_alg, 
                          key=key, iv=iv, op=op)          
    
    
    def aes_encrypt(self, key, msg, iv=None):
        """
        Encrypt msg from the key (which is assumed to be in plain
        text - not encoded).
        """             
        #Decode the key and iv if necessary
        #key = b64decode(key)             
        if iv is None:                 
            iv = '\0' * 16             
        else:                 
            iv = base64.b64decode(iv)
            
        # Return the encryption function             
        def encrypt(data):                 
            cipher = self.aes_build_cipher(key, iv, self.ENC)                 
            v = cipher.update(data)                 
            v = v + cipher.final()                 
            del cipher                 
            v = base64.b64encode(v)                 
            return v             
        
        #print "AES encryption successful\n"             
        return encrypt(msg)         
        
    def aes_decrypt(self, key, msg, iv=None):             
        """
        Decrypt msg from the key (which is assumed to be in plain
        text - not encoded).
        """             
            
        # Decode the key and iv             
        # key = b64decode(key)             
        if iv is None:                 
            iv = '\0' * 16             
        else:                 
            iv = base64.b64decode(iv)             
            
        # Return the decryption function             
        def decrypt(data):                 
            data = base64.b64decode(data)                 
            cipher = self.aes_build_cipher(key, iv, self.DEC)                 
            v = cipher.update(data)                 
            v = v + cipher.final()                 
            del cipher                 
            return v             
        #print "AES decryption successful\n"             
        return decrypt(msg) 

    def aes_test(self, key, msg):
        
        # some random lengths 
        msg_len = 50
        key_len = 10 
        
        # Generate randome strings if necessary
        chars=string.ascii_uppercase + string.digits
        if msg == None: 
            msg = ''.join(random.choice(chars) \
                                     for x in range(msg_len)) 
        if key == None: 
            key = ''.join(random.choice(chars) \
                                     for x in range(key_len)) 

        enc_msg=auth.aes_encrypt(key=key,msg=msg)

        print "AES Encryption testing"
        print "Original text ", msg
        print "Encrypted encoded text ", enc_msg

        dec_msg=auth.aes_decrypt(key=key,msg=enc_msg) 
        print "decrypted text ", dec_msg
        if (msg == dec_msg):
            print "AES encryption successful"
        else:
            print "AES encryption FAILED!" 

if __name__ == '__main__':
    assert(sys.argv)
    if len(sys.argv) < 2:
        print """
Error: command line should specify a config file.

Usage: crypt.py <config-file>

$ cat example.cfg
common: { 
    private_key: 'fixtures/public_key.pem', # note that public refers to
    public_cert: 'fixtures/public_cert.pem', # public AuA 
}
crypt: {
    command: "test",
    msg: "qwrtttrtyutyyyyy",
    key: "sdkfsdfldfh123213213" 
}
"""    
        sys.exit(1) 

    cfg = Config(sys.argv[1]) 
    
    if (cfg.crypt.command == "test"):
        auth = AuthCrypt(cfg=cfg,
                         pub_key=cfg.common.public_cert,
                         priv_key=cfg.common.private_key) # production

        print "certificate expiry = ", auth.x509_get_cert_expiry()
        auth.x509_test() 

        msg = cfg.crypt.msg 
        key = cfg.crypt.key
        auth.aes_test(key, msg) 

    else:
        raise Exception("Unknown command") 
    
