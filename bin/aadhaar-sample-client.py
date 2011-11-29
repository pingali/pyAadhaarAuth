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
Simplest possible python client
"""
import logging
import sys, os, os.path 
from config import Config 
import simplejson as json 

def findpath(path):
    return os.path.abspath(os.path.join(os.path.dirname(__file__),path))

log = logging.getLogger("SampleClient")

from AadhaarAuth.request import AuthRequest
from AadhaarAuth.data import AuthData
from AadhaarAuth.command import AuthConfig
from AadhaarAuth.response import AuthResponse 

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"

if __name__ == '__main__':
    
    cmd = AuthConfig() 
    cfg = cmd.update_config() 

    logging.getLogger().setLevel(cfg.common.loglevel) 
    logging.basicConfig()
    
    # This is a simple client. Force use of name
    cfg.request.demographics = ["Pi"]
    cfg.request.biometrics = []
    
    # => Gather the data from the (simulated) client
    data = AuthData(cfg=cfg) 
    data.generate_client_xml() 
    exported_data = data.export_request_data() 

    # Create the request object and execute 
    req = AuthRequest(cfg)
    req.import_request_data(exported_data)
    req.execute()

    # Load the response 
    data = json.loads(req.export_response_data())
    res = AuthResponse(cfg=cfg, uid=cfg.request.uid) 
    res.load_string(data['xml'])
            
    # Find all the attributes set 
    bits = res.lookup_usage_bits()
    print "[%.3f] (%s) -> %s " % (data['latency'], bits, data['ret'])
    if data['err'] is not None and data['err'] != -1: 
        print "Err %s: %s "% ( data['err'], data['err_message'])
