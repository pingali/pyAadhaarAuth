#!/usr/bin/env python
#
# $Id: sign3.py 363 2006-01-01 18:03:07Z valos $
#
# PyXMLSec example: Signing a file with a dynamicaly created template and
# an X509 certificate.
#
# Signs a file using a dynamicaly created template, key from PEM file and
# an X509 certificate. The signature has one reference with one enveloped 
# transform to sign the whole document except the <dsig:Signature/> node 
# itself. The key certificate is written in the <dsig:X509Data/> node.
#
# This example was developed and tested with OpenSSL crypto library. The 
# certificates management policies for another crypto library may break it.
#
# Usage: 
#	./sign3.py <xml-doc> <pkcs12-file> <password>
#
# Example:
#	./sign3.py sign3-doc.xml public.p12 hello > sign3-res.xml
#
# The result signature could be validated using verify3 example:
#	./verify3.py sign3-res.xml rootcert.pem
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
# 
# Copyright (C) 2003-2004 Valery Febvre <vfebvre@easter-eggs.com>
#


#
# authrequest_signature 
#
# usage: 
#       python authrequest_signature.py <xmlfile> 
# 
#       The xml file can contain the signature template or not. 
#       The code can handle both situations. Right now does
#       not have a way to verify the result. 
#
#

import os, sys
import libxml2
import xmlsec
from config import Config 
from M2Crypto import RSA, BIO, Rand, m2, EVP, X509


class AuthRequestSignature(): 
    
    def __init__(self, use_template=False): 
        self.dsig_ctx = None
        self._init_xmlsec = False 
        self._use_template = use_template
        return 
        
    def init_xmlsec(self): 

        # Init libxml library
        libxml2.initParser()
        libxml2.substituteEntitiesDefault(1)
        
        # Init xmlsec library
        if xmlsec.init() < 0:
            print "Error: xmlsec initialization failed."
            # XXX This should do something else...
            return sys.exit(-1)
        
        # Check loaded library version
        if xmlsec.checkVersion() != 1:
            print "Error: loaded xmlsec library version is not compatible.\n"
            sys.exit(-1)

        # Init crypto library
        if xmlsec.cryptoAppInit(None) < 0:
            print "Error: crypto initialization failed."
            
        # Init xmlsec-crypto library
        if xmlsec.cryptoInit() < 0:
            print "Error: xmlsec-crypto initialization failed."

        self._init_xmlsec = True 

    def shutdown_xmlsec(self):
        
        if not self._init_xmlsec:
            return 

        # Shutdown xmlsec-crypto library
        xmlsec.cryptoShutdown()

        # Shutdown crypto library
        xmlsec.cryptoAppShutdown()

        # Shutdown xmlsec library
        xmlsec.shutdown()

        # Shutdown LibXML2
        libxml2.cleanupParser()


    # Signs the xml_file using private key from pkcs_file and dynamicaly
    # created enveloped signature template. The certificate from cert_file
    # is placed in the <dsig:X509Data/> node.
    # Returns 0 on success or a negative value if an error occurs.
    def sign_file(self, xml_file, pkcs_file, password):
        assert(xml_file)
        assert(pkcs_file)
        assert(password)
        
        # Load template
        if not self.check_filename(xml_file):
            return -1
        
        doc = libxml2.parseFile(xml_file)
        if doc is None or doc.getRootElement() is None:
            print "Error: unable to parse file \"%s\"" % xml_file
            return self.cleanup(doc)
        
        
        if self._use_template: 
            # If the template is already in the text ready to be filled 
            signNode = xmlsec.findNode(doc.getRootElement(),
                                       xmlsec.NodeSignature, 
                                       xmlsec.DSigNs);
            if signNode is None:
                print "Error: failed to find signature template"
                return self.cleanup(doc)
                
        else:
            # If the signature structure has to be constructed and added.
            
            # Create signature template for RSA-SHA1 enveloped signature
            signNode = xmlsec.TmplSignature(doc, xmlsec.transformExclC14NId(),
                                            xmlsec.transformRsaSha1Id(), None)
            
            # Add <dsig:Signature/> node to the doc
            doc.getRootElement().addChild(signNode)
            
            # Add reference
            refNode = signNode.addReference(xmlsec.transformSha1Id(),
                                            None, None, None)
            if refNode is None:
                print "Error: failed to add reference to signature template"
                return self.cleanup(doc)
            
            # Add enveloped transform
            if refNode.addTransform(xmlsec.transformEnvelopedId()) is None:
                print "Error: failed to add enveloped transform to reference"
                return self.cleanup(doc)
        
            # Add <dsig:KeyInfo/> and <dsig:X509Data/>
            keyInfoNode = signNode.ensureKeyInfo(None)
            if keyInfoNode is None:
                print "Error: failed to add key info"
                return self.cleanup(doc)
            
            if keyInfoNode.addX509Data() is None:
                print "Error: failed to add X509Data node"
                return self.cleanup(doc)
            
        # Create signature context, we don't need keys manager in this
        # example
        dsig_ctx = xmlsec.DSigCtx()
        if dsig_ctx is None:
            print "Error: failed to create signature context"
            return self.cleanup(doc)
        
        # Store the context..
        self.dsig_ctx = dsig_ctx 

        # Load private key, assuming that there is not password
        if not self.check_filename(pkcs_file):
            return self.cleanup(doc, dsig_ctx)
        
        #key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
        #                              None, None, None)
        key = xmlsec.cryptoAppPkcs12Load(pkcs_file, password, None, None)
        if key is None:
            print "Error: failed to load private pem key from \"%s\"" % pkcs_file
            return self.cleanup(doc, dsig_ctx)

        dsig_ctx.signKey = key
        
        # Load certificate and add to the key
        # if not check_filename(cert_file):
        #    return cleanup(doc, dsig_ctx)
        # if xmlsec.cryptoAppKeyCertLoad(key, cert_file, xmlsec.KeyDataFormatPem) < 0:
        #    print "Error: failed to load pem certificate \"%s\"" % cert_file
        #    return cleanup(doc, dsig_ctx)
        
        # Set key name to the file name, this is just an example!
        if key.setName(pkcs_file) < 0:
            print "Error: failed to set key name for key from \"%s\"" % pkcs_file
            return self.cleanup(doc, dsig_ctx)
        
        # Sign the template
        if dsig_ctx.sign(signNode) < 0:
            print "Error: signature failed"
            return self.cleanup(doc, dsig_ctx)
        
        # Print signed document to stdout
        #doc.dump("-")
        #doc.formatDump("-", 0)
        import libxml2mod
        libxml2mod.xmlDocFormatDump("-", doc._o, 0)

        # Success
        return self.cleanup(doc, dsig_ctx, 1)

    
    def cleanup(self, doc=None, dsig_ctx=None, res=-1):
        if dsig_ctx is not None:
            dsig_ctx.destroy()
            if doc is not None:
                doc.freeDoc()
        return res
            

    def check_filename(self, filename):
        if os.access(filename, os.R_OK):
            return 1
        else:
            print "Error: XML file \"%s\" not found OR no read access" % filename
            return 0

if __name__ == "__main__":
    assert(sys.argv)
    if len(sys.argv) < 2:
        print "Error: wrong number of arguments."
        print "Usage: %s <xml-tmpl> " % sys.argv[0]
        print "" 
        print "Note that there are three implicit arguments (from config file)"
        print "    pkcs12 - signer's p12 files"
        print "    password - password for the p12 files" 
        print "    use_template - whether the xml has signature template or not"
        print "They are obtained from the auth.cfg file" 
        print "" 
        sys.exit(1)
    
    cfg = Config('auth.cfg')  
    x = AuthRequestSignature(cfg.request.use_template) 
    x.init_xmlsec() 
    res = x.sign_file(sys.argv[1], 
                      cfg.request.local_pkcs_path, 
                      cfg.request.pkcs_password)
    x.shutdown_xmlsec() 
    sys.exit(res)
