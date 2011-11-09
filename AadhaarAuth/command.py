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

import os.path, sys 
from config import Config, ConfigMerger 
from optparse import OptionParser, SUPPRESS_HELP
import logging 
log=logging.getLogger('AuthConfig')

__author__ = "Venkata Pingali"
__copyright__ = "Copyright 2011,Venkata Pingali and TCS" 
__credits__ = ["UIDAI", "MindTree", "GeoDesic", "Viral Shah"] 
__license__ = "MIT"
__version__ = "0.1"
__maintainer__ = "Venkata Pingali"
__email__ = "pingali@gmail.com"
__status__ = "Pre-release"

class AuthConfig(): 
    """
    Parse the command line
    """
    def __init__(self,name, summary):
        """
        Initialize command object with information about the target
        configuration (e.g., 'request') and appropriate help text
        (e.g., 'Processes authentication requests'
        """
        self._name = name
        self._summary = summary 

    def show_example_config(self, option, opt_str, value, parser):
        current_directory = os.path.dirname(__file__)
        cfg = file(current_directory + '/fixtures/auth.cfg').read() 
        print cfg
        
    def update_config(self): 
        """
        Process each element of the command line and generate a target
        configuration.
        """
        usage = "usage: %prog [options] [<attrib=value> <attrib=value>...]\n" \
            + self._summary
        
        parser = OptionParser(usage=usage)
        
        #=> Set the help text and other command line options. 
        parser.add_option("-c", "--config",
                          action="store", type="string", dest="config_file",
                          default="fixtures/auth.cfg", 
                          help="Specify the input configuration file. " + 
                          "(default: auth.cfg)",
                          metavar="FILE")
        parser.add_option("--show-example-config",
                          action="callback", callback=self.show_example_config, 
                          help="Sample configuration file")

        defaults = {
            'request': 'request_demo',
            'response': 'response_validate',
            'crypt': 'crypt_test',
            'sign': 'sign_default',
            'validate': 'validate_xml_only',
            'batch': 'batch_default'
            }
        
        # => For a given command (e.g., response.py), enable the help
        # text for that config element. For everything else, suppress
        # help. Make the options secret. 
        
        for k, v in defaults.items():
            if (k == self._name):                 
                help_text=\
"""Specify the configuration instance to use for %s. For example, %s. See
available choices in config file. (default: %s)""" % (k, v, v)
            else:
                help_text=SUPPRESS_HELP
            parser.add_option("--" + k,
                              action="store", type="string", 
                              dest=k, default=v, 
                              metavar="NAME",
                              help=help_text)
        
        # parse the command line
        (options, args) = parser.parse_args()
        
        # Check if the configuration file exists 
        if (not os.path.isfile(options.config_file)):
            raise Exception("Unknown config file %s " % (options.config_file))

        # Read the configuration file
        cfg = Config(options.config_file)

        # => For the target configuration element (e.g., request or
        # response) check whether the target configuration is valid
        cmd = "cfg[options.%s]" %  self._name
        try: 
            target_config = eval(cmd)
        except:
            raise Exception("Invalid setting for parameter \'%s\'. Please check the configuration file." % self._name)

        # => Update the configuration for the particular service 
        log.warn("Overriding existing request with %s " % \
                     (eval("options.%s" % self._name)))
        cmd = "cfg.%s=cfg[options.%s]" %  (self._name, self._name) 
        exec(cmd) 
        
        # python <command> --conf=auth.cfg a=x c.d=y Over ride
        # individual parameters of the config file.  Note that you can
        # override pretty much any config element. If there is a '.'
        # in the variable name, then it is assumed to refer to full
        # path of the config element (e.g., batch.json). If there is
        # no '.', it is assumed to refer to only the configuration
        # element corresponding to the command (e.g., request).
        param_hash = {}
        for idx, arg in enumerate(args):
            parts = arg.split('=', 1)
            if len(parts) < 2:         
                # End of options, don't translate the rest.
                # newargs.extend(sys.argv[idx+1:])
                break    
            argname, argvalue = parts     
            param_hash[argname] = argvalue 
        log.debug("Command line parameter options = " +  param_hash.__str__())
            
        # Print the updated configuration element
        log.debug("Configuration of target element '%s':\n%s " % (self._name, cfg[self._name]))
        
        # Update the 
        for k,v in param_hash.items(): 
            if "." not in k: 
                # here we are updating only the config element
                # corresponding to the command.
                cfg[self._name][k] = v 
                print cfg[self._name] 
            else: 
                cmd = "cfg.%s=\'%s\'" % (k, v)
                exec(cmd) 
                cmd = "cfg.%s" % k 
                log.debug("Updated conf var %s to %s \n" % (cmd, eval(cmd)))
        
        log.debug("Final configuration:\n%s" % cfg)
        return cfg 

if __name__ == "__main__": 
    name = "request" 
    summary = "Issues authentication requests to the server" 
    
    logging.getLogger().setLevel(logging.WARN) 
    logging.basicConfig(filename="execution.log") 
    c = AuthConfig(name, summary)
    cfg = c.update_config()

