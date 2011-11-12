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
ASA/AUA client. This will eventually be a AUA server to which the field
client will do a post to the ASA server based on configuration. 
"""

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"

import sys 
from config import Config 
import json 
import requests 
import logging


from AadhaarAuth.data import AuthData

class ASAClient(): 
    
    def __init__(self, cfg): 
        self._cfg = cfg 

    def request(self): 

        data = AuthData(cfg=self._cfg) 
        data.generate_xml() 
        json_data = data.export_request_data() 
        
        print json.loads(json_data) 

        headers = {'Content-Type': 'application/json'}
        r = requests.post("http://127.0.0.1:8000/authenticate", 
                          data=json_data, headers=headers) 

        print r 
        print r.headers 
        print r.content 

if __name__=="__main__":
    
    assert(sys.argv)
    if len(sys.argv) < 3:
        print "Usage: simple-client.py <config-file> <uid> <name>"
        sys.exit(1) 

    # Load sample configuration 
    cfg = Config(sys.argv[1])
    
    logging.getLogger().setLevel(cfg.common.loglevel) 
    logging.basicConfig()
    
    # Update the request information 
    cfg.request.uid = sys.argv[2]
    cfg.request.demographics = ["Pi"]
    cfg.request.biometrics = []
    cfg.request['Pi'] = {
        'ms': "E",
        'name': sys.argv[3]
     }

    asaclient = ASAClient(cfg=cfg) 
    asaclient.request() 


