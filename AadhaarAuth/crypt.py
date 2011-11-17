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
from command import AuthConfig 

import logging
log=logging.getLogger("AuthCrypt") 

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
        
        log.debug("x509 Encrypting using cert %s" % self._public_key)
        
        x509 = X509.load_cert(self._public_key)
        rsa = x509.get_pubkey().get_rsa()
        enc_data=rsa.public_encrypt(data, RSA.pkcs1_padding)
        return enc_data
    
    # Decryption of data requires private key. Assumes the data is 
    # base64 encoded. 
    def x509_decrypt(self, data):
        """
        Decrypt using private key (works only if the private key is
        set as well - so non UIDAI).
        """
        if (data == None or data == ""):
            raise Exception("No data to encrypt") 

        log.debug("x509 Decrypting using cert %s " % self._private_key)
        log.debug("Decrypting data: \"%s\"" % base64.b64encode(data))

        rsa = RSA.load_key(self._private_key) 
        res = rsa.private_decrypt(data, RSA.pkcs1_padding)
        #log.debug("\"%s\"" % (res))
        return res 
    
    def x509_test(self, show=True): 
        """
        Test whether x509 encryption and decryption are working as
        expected (works only with non-UIDAI cert/key pairs because we 
        dont have access UIDAI private key).
        """
        data = "39jsjsfdhdshfd" # some test data
        if show:
            log.debug("Encryption payload: %s " % data)
        enc_data = self.x509_encrypt(data)
        if show:
            log.debug("Encrypted base64 encoded data:")
            log.debug(base64.b64encode(enc_data))
        dec_data = self.x509_decrypt(enc_data)
        if show:
            log.debug("Decrypted data")
            log.debug(dec_data)
        
        if (data != dec_data): 
                    
            raise Exception("Encryption is not functioning correctly")
        else:
            if show:
                log.debug("Encrytion payload and decrypted data matched")
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
            return v             
        
        #log.debug("AES encryption successful\n")
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
            cipher = self.aes_build_cipher(key, iv, self.DEC)                 
            v = cipher.update(data)                 
            v = v + cipher.final()                 
            del cipher                 
            return v             
        #log.debug("AES decryption successful\n")
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

        log.debug("AES Encryption testing")
        log.debug("Original text %s " % msg)
        log.debug("Encrypted encoded text %s " % base64.b64encode(enc_msg))

        dec_msg=auth.aes_decrypt(key=key,msg=enc_msg) 
        log.debug("decrypted text %s " % dec_msg)
        if (msg == dec_msg):
            log.debug("AES encryption successful")
        else:
            log.error("AES encryption FAILED!")

if __name__ == '__main__':

    cmd = AuthConfig("crypt", "Encryption and decryption capability")
    cfg = cmd.update_config() 

    #=> Setup logging 
    logging.basicConfig(
	#filename=cfg.common.logfile, 
	format=cfg.common.logformat)

    logging.getLogger().setLevel(cfg.common.loglevel)
    log.info("Starting my AuthCrypt client")
    
    if (cfg.crypt.command == "test"):
        auth = AuthCrypt(cfg=cfg,
                         pub_key=cfg.common.public_cert,
                         priv_key=cfg.common.private_key) # production

        log.debug("certificate expiry = %s " % auth.x509_get_cert_expiry())
        auth.x509_test() 

        msg = cfg.crypt.msg 
        key = cfg.crypt.key
        auth.aes_test(key, msg) 

    else:
        raise Exception("Unknown command") 
    
