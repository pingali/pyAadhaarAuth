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

import os, os.path, sys


def findpath(path):
    return os.path.abspath(os.path.join(os.path.dirname(__file__),path))

# For dumper library 
import AadhaarAuth
auth_path = os.path.dirname(os.path.realpath(AadhaarAuth.__file__))
sys.path.append(auth_path + "/lib") 

import copy 
import logging
from lxml import etree, objectify 
import tempfile 
import dumper 
import hashlib, hmac, base64, random 
from config import Config 
import traceback 
from datetime import datetime
from M2Crypto import Rand 
import json
from pprint import pprint

from AadhaarAuth.request import AuthRequest
from AadhaarAuth.data import AuthData
from AadhaarAuth.command import AuthConfig
from AadhaarAuth.response import AuthResponse 

log = logging.getLogger("AuthBatchRequest")

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"


"""
Issue batch requests to the server
"""
class AuthBatchRequest():
    """
    Issue batch requests to the server 
    """    

    def __init__(self, cfg): 
        self._cfg = cfg 
        self._json_file = cfg.batch.json
    
    def load_data(self): 
        """
        Load json data
        """
        fp=open(self._json_file)
        self._data = json.load(fp)
        fp.close()

    def authenticate_basic(self): 
        
        log.debug("Authenticating") 

        for person in self._data: 
            cfg= self._cfg 
            cfg.request.uid = person['uid'] 
            cfg.request.demographics = ["Pi"]
            cfg.request.biometrics = ["FMR"]
            cfg.request['Pi'] = {
                'ms': "E",
                'name': person['name']
                }
            cfg.request["FMR"] = { 
                'bio': person['bio']
                }

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
    def authenticate_advanced(self): 
        
        log.debug("Authentication advanced") 

        for person in self._data: 

            cfg= self._cfg 
            cfg.request.uid = person['uid'] 
            cfg.request.demographics = ["Pi", "Pa"]
            cfg.request.biometrics = []
            
            # test data format is DD-MM-YYYY whereas what is required
            # is YYYY-MM-DD 
            dob = person['dob'] 
            dob_split = dob.split("-") 
            dob = dob_split[2] + "-" + dob_split[1] + "-" + dob_split[0]
            cfg.request['Pi'] = {
                'ms': "E",
                'name': person['name'],
                'dob': dob,
                'gender': person['gender'], 
                }
            cfg.request["Pa"] = { 
                'ms': "E",
                "landmark": person['landmark'],
                "street": person['street'], # 12 Maulana Azad Marg
                "locality": person['locality'], #"",
                "poname": person['poname'], #"",
                "vtc": person['vtc'], #"New Delhi",
                "subdist": person['subdist'], #"New Delhi",
                "district": person['district'], #"New Delhi",
                "state": person['state'], #"New delhi",
                "pincode": person['pincode'] #"110002",
                }

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

if __name__ == '__main__':
       
    logging.basicConfig() 

    cmd = AuthConfig('batch', "Batch processing") 
    cfg = cmd.update_config() 

    #=> Setup logging 
    logging.getLogger().setLevel(logging.WARN) #cfg.common.loglevel )
    logging.basicConfig(
	#filename='execution.log',
	format='%(asctime)-6s: %(name)s - %(levelname)s - %(message)s') 

    log.info("Starting my Batch AuthClient")

    batch = AuthBatchRequest(cfg=cfg)
    batch.load_data() 
    batch.authenticate_basic() 
    batch.authenticate_advanced() 
