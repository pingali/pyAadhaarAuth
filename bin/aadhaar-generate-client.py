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
Prepare working space for writing client code
"""
import logging
import os, os.path, sys 
#from shutil import copy, copytree
from distutils import dir_util, file_util
import AadhaarAuth 

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"


def which(program):     

    def is_exe(fpath):         
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)      
    
    for path in os.environ["PATH"].split(os.pathsep):
        exe_file = os.path.join(path, program)             
        if is_exe(exe_file):                 
            return exe_file      
    return None 

if __name__ == '__main__':
    assert(sys.argv)
    if len(sys.argv) < 2:
        print "Usage: aadhaar-generate-client.py <working-directory>"
        print "Populates a working directory "
        sys.exit(1) 

    logging.basicConfig()
    
    working_directory=sys.argv[1] 
    if (not os.path.isdir(working_directory)):
        raise Exception("Invalid path. Should be a directory")
    
    print "Preparing working space for Aadhaar client development..." 
    
    # Copy the sample client
    sample_client_path = which('aadhaar-sample-client.py')
    file_util.copy_file(sample_client_path, working_directory, update=1) 
    
    # copy the directory 
    auth_module_path = os.path.dirname(AadhaarAuth.__file__)
    dir_util.copy_tree(auth_module_path + "/fixtures", working_directory + "/fixtures", update=1)
    
    print """
Following have been copied:

    aadhaar-sample-client.py : simple aadhaar client

    fixtures: directory with sample configuration files and 
        required certificate files

Please update the fixtures/auth.cfg - the configuration file which 
is the input to the sample client to reflect your application context. 
Please double check all paths and values before running the client.
Where possible, please give absolute paths. 
""" 
    
       
