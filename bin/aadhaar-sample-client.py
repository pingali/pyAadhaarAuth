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

from AadhaarAuth.request import AuthRequest
from AadhaarAuth.data import AuthData


__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"

if __name__ == '__main__':

    assert(sys.argv)
    if len(sys.argv) < 3:
        print "Usage: aadhaar-sample-client.py <config-file> <uid> <name>"
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

    # use this for biometrics query 
    #cfg.request.uid = sys.argv[2]
    #cfg.request = cfg.request_bio  
    
    # => Gather the data from the (simulated) client
    data = AuthData(cfg=cfg) 
    data.generate_client_xml() 
    exported_data = data.export_request_data() 

    # Create the request object and execute 
    req = AuthRequest(cfg)
    req.import_request_data(exported_data)
    req.execute()
