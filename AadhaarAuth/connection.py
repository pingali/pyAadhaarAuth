#!/usr/bin/env python
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

import requests 
from config import Config 

import os, os.path, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/lib")
import dumper 
import time 
import traceback 

class AuthConnection():
    """
    Connection manager for authentication requests. For now it treats
    each authentication request as being separate and closes the
    connection when done. Down the line it will keep connection open 
    and process multiple requests 
    """
    
    def __init__(self, cfg, ac=None, keepopen=False): 
        self._ac = ac 
        self._keepopen = keepopen # To be used down the line
        self._cfg = cfg 

    def set_ac(self, ac):
        """
        Update the AUA code
        """
        self._ac = ac 

    def authenticate(self, uid, data): 
        """
        Open a connection to auth server, post the xml and look at
        the response 
        """
        url_base=self._cfg.common.auth_url
        url = "%s/%s/%s/%s" %(url_base, self._ac, uid[0],uid[1])
        try: 
            start_time = time.time()
            r = requests.post(url, data)
            end_time = time.time()
            call_time = end_time-start_time
            
        except: 
            print traceback.print_exc(file=sys.stdout)
            print r.headers 
            print r.content 
            raise Exception("Unable to authenticate") 

        return [call_time, r.content] 

if __name__ == '__main__':
    
    cfg = Config('fixtures/auth.cfg') 
    xml = file('fixtures/authrequest.xml').read() 
    a = AuthConnection(cfg, "public") 
    res = a.authenticate("999999990019", xml)
    print res 


