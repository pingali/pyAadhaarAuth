#!/usr/bin/python
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

"""
ASA/AUA server that will accept XML from the field, package it and
communicate with the server.
"""

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"

import cherrypy
import json 
import os, sys
import logging
from config import Config 
from AadhaarAuth.request import AuthRequest

__all__ = ['ASAServer']

class ASAServer:
    """
    Absolutely minimal ASA server. Several things will be added
    including the addition to wrapping the incoming XML and signing
    it.
    """
    def __init__(self, cfg): 
        self._cfg = cfg 

    @cherrypy.expose 
    def authenticate(self):
        
        #=> Validate incoming request 
        valid_content_types=['text/json', 'application/json']
        ct = cherrypy.request.headers.get('Content-Type', None)
        if ct not in valid_content_types:
           raise cherrypy.HTTPError(415, 'Unsupported Media Type')
       
        # CherryPy will set the request.body with a file object
        # where to read the content from
        if hasattr(cherrypy.request.body, 'read'):
            jsoned_request_data= cherrypy.request.body.read()
            print json.loads(jsoned_request_data)
            
            req = AuthRequest(cfg=self._cfg)
            req.import_request_data(jsoned_request_data)
            req.execute() 

            jsoned_response_data = req.export_response_data() 
            print json.loads(jsoned_response_data) 

            cherrypy.response.headers['Content-Type']='text/json'
            
            # XXX This is simply echoing the input. This should
            # eventually call the UIDAI server. 
            return jsoned_response_data
        else:
            raise cherrypy.HTTPError(400, 'Bad Request')

conf = {
    'global': {
        'server.socket_host': '127.0.0.1',
        'server.socket_port': 8000,
        },
    #'/': {
    #    'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
    #}
    }

assert(sys.argv)
if len(sys.argv) < 2:
    print "Usage: aadhaar-asa-server.py <config-file>"
    sys.exit(1) 

# Load sample configuration 
cfg = Config(sys.argv[1])

logging.getLogger().setLevel(cfg.common.loglevel) 
logging.basicConfig()

cherrypy.quickstart(ASAServer(cfg), '/', conf)
