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
#
#from xml.dom.minidom import Document
## Create the minidom document
#doc = Document()
## Create the <wml> base element
#wml = doc.createElement("wml")
#doc.appendChild(wml)
## Create the main <card> element
#maincard = doc.createElement("card")
#maincard.setAttribute("id", "main")
#wml.appendChild(maincard)
## Create a <p> element
#paragraph1 = doc.createElement("p")
#maincard.appendChild(paragraph1)
## Give the <p> elemenet some text
#ptext = doc.createTextNode("This is a test!")
#paragraph1.appendChild(ptext)
## Print our newly created XML
#print doc.toprettyxml(indent="  ")
#
