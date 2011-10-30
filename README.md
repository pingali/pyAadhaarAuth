
Python Client for UIDAI authentication service
=============================================

Status
------

Skeleton code (not primetime) 
Simplest possible XSD-compliant XML is generated for request and response 
Incoming XML can be validated and 'objectified for both 

To do
-----

1. Use the objectified xml to populate internal state 
2. Look through the spec for validation rules beyond what the 
XSD is providing (e.g., sanity checks) 
3. Add pyxmlsec processing 
4. Look into integration with biometrics

Running 
-------

>$ sudo apt-get install python-dev libxml2-dev libxslt1-dev libxmlsec1 libxmlsec1-dev 
>$ sudo pip install lxml 
>$ sudo pip install pyxmlsec 
>$ python authrequest.py 
><Auth txn="" ac="public" xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" ver="1.5" uid="123412341234" tid="" sa="public">
>  <Skey ci="23233">ZWhoc2tz</Skey>
>  <Uses pfa="n" bio="n" pin="n" pa="n" otp="n" pi="y"/>
>  <Data>ZGZkc2ZkZmRz</Data>
></Auth>
>
>The XML generated is XSD compliant
>Validating this incoming XML
><?xml version="1.0"?> 
><Auth xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" 
>      ver="1.5" tid="public" ac="public" sa="public" 
>      lk="MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ=" uid="999999990019" 
>      txn="GEO.11051880"> 
>      <Skey ci="20131003">Nc6DrZKFk1oQXxfgnFUl0mmtYYIPl0RGaFd2oINkpChU1++xdddMx6Dlbz6mEYs3 
>            IyzChGjRXN5/al9r0runFX8LspTfMchwpxaaDIOyIUguBoYmPUqJDqTQcwey6Ntc 
>            TJWFSgOvBg+omUkdbK/9GOQ5KWWrN+E0A9JN0IPU4IJqJZmsA6ETZlVoZteYtoMI 
>            Ucv53qmxNPOEmJ3s4BC3ppHRRWRFMUp/eW7DFJ33W+uInZB6yekKE0dz8fYeo03w 
>            2JUT1wlafL7aseb04nv5tNEbllHWafmbMpbv2pXKr+WPgytjrygt1LagGqF4a5Mr 
>            /UTNwsy4m/YwlkWN0QcYVw== 
>      </Skey> 
>      <Uses otp="n" pin="n" bio="n" pa="n" pfa="n" pi="y" /> 
>      <Data>YOn05vg5qMwElULpEmdiH0j6rM1XWcbQN0n+CFNQeazouCgjyPBH/a2SwbFgq/fF 
>            CYUm+the8gQyYC36VO49NLcNcD7WdMhweoiDYgJoCX/t87Kbq/ABoAetfX7OLAck 
>            /mHrTmw8tsfJgo4xGSzKZKr+pVn1O8dDHJjwgptySr7vp2Ntj6ogu6B905rsyTWw 
>            73iMgoILDHf5soM3Pvde+/XW5rJD9AIPQGhHnKirwkiAgNIhtWU6ttYg4t6gHHbZ 
>            0gVBwgjRzM3sDWKzK0EnmA== 
>      </Data> 
>      <Hmac>xy+JPoVN9dsWVm4YPZFwhVBKcUzzCTVvAxikT6BT5EcPgzX2JkLFDls+kLoNMpWe 
>      </Hmac> 
></Auth> 
>
>The XML generated is XSD compliant
>
>$ python authresponse.py
><?xml version="1.0"?>
><AuthRes info="" txn="" code="-1" err="100" ts="2011-10-30T13:30:35" ret="n" xmlns="http://www.uidai.gov.in/authentication/uid-auth-response/1.0"/>
>
>The XML generated is XSD compliant
>Validating this incoming XML
><?xml version="1.0"?> 
><AuthRes  xmlns="http://www.uidai.gov.in/authentication/uid-auth-response/1.0"
>	  ret="y" code="52" 
>	  txn="322hfdjhsjkdhfjkds" err="100" info="" 
>	  ts="2011-10-30T13:26:19"></AuthRes>
>
>The XML generated is XSD compliant
>

Notes
-----

1. XSD file parsing 

Right now the XSD file is read each time and a parser instantiated.
Only lxml seems to be working. Code generationg using generateDS and
pyxb are throwing different errors that require non-trivial debugging
effort. Workaround: The application can store the generated parser.

2. Signatures 

The XSD files do not automatically include the digital
signatures. They specify the message structure without the
dignature. The signature processing is pre/post processing step as
required.

Background
-----------
The basic requirement is to generate XML messages to be sent 
to the auth server and processing the received messages. This 
can be achieved in multiple ways: 

1. Write custom code to build the XML around the xml.domutils 
or lxml and use the XSD to validate the generated xml only. 

2. Build a XSD and use a class generator from that. This makes life
easier but it is lot more sensitive to the structure and evolution
of the XSD, and is intolerant of XSD-incompatible  messages from the 
server. There are three 'objectify' modules 
  (a) Gnosis Utils 
  (b) lxml 
  (c) generateDS 
  (d) pyxb 

3. Build a JSON eventually turn the JSON into XML. This has the
advantage that json handling is much easier. However the xml 
signatures might pose a problem (not sure).

======================================================================

Other notes in case it is useful

Instructions for installing Gnosis_Utils
-----------------------------------------

$ wget http://gnosis.cx/download/Gnosis_Utils-1.2.2.tar.gz
$ tar zxvf Gnosis_Utils-1.2.2.tar.gz 
$ cd Gnosis_Utils 
$ Apply the following patch 
--- setup.py.orig	2011-10-29 21:42:24.850114295 +0530
+++ setup.py	2011-10-29 21:42:34.850114291 +0530
@@ -205,7 +205,7 @@
 copy_all_files = 1
 
 def copy_extra_files():
-    destroot = glob(os.path.join('build','lib'))[0]
+    destroot = os.path.join('build','lib')
 
     # go through MANIFEST to see what is supposed to be under build directory
     print "Copying extra files to %s ..." % destroot
$ sudo python setup.py build 
$ sudo python setup.py install

Generating XSD 
---------------

There is no XSD that is distributed with the uid auth client. So we have
to generate it first from the sample XSDs available. There is a java 
tool for this.

Download this jar file
http://www.thaiopensource.com/relaxng/trang-manual.html#running

$java -jar trang.jar <xml> <xsd> 

If there are non-UTF characters, 
(a) look for "" They dont get copied well especially from the html
and from PDFs 
(b) $ sed -i 's/[\d128-\d255]//g' <xml> 
This will clean up the text

Links 
------

Validating XML against DTD
http://code.activestate.com/recipes/220472/

xmlsec example code
http://pyxmlsec.labs.libre-entreprise.org/index.php?section=examples

