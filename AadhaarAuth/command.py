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
import traceback 

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
    def __init__(self,name="unknown", summary="Unknown commands",
                 cfg=None):
        """
        Initialize command object with information about the target
        configuration (e.g., 'request') and appropriate help text
        (e.g., 'Processes authentication requests'
        """
        self._name = name
        self._summary = summary 
        self._cfg = cfg
        
    def get_path(cfg, path): 
        try: 
            if path.startswith("/"): 
                # dont do anything
                return path
            basedir = cfg.common.dir 
            return basedir + "/" + path 
        except: 
            return None 

    def show_example_config(self, option, opt_str, value, parser):
        current_directory = os.path.dirname(__file__)
        cfg = file(current_directory + '/fixtures/auth.cfg').read() 
        print cfg
        sys.exit(0) 

    def update_paths(self, cfg): 
        """
        Take relative paths of various files and make it absolute
        """
        # first introduce a dir element
        paths = ['common.private_key', 'common.public_cert', 
                 'common.pkcs_path', 'common.uid_cert_path',
                 #'common.logfile',
                 #'request_demo.xml', 'request_demo.signedxml',
                 #'request_bio.xml', 'request_bio.signedxml',
                 'response_validate.xml',
                 'signature_default.xml', 'signature_default.signedxml',
                 'signature_verify.signedxml', 'validate_xml_only.xml',
                 'batch_default.json'] 
        basedir = cfg.common.dir 
        for p in paths: 
            try: 
                old_path = eval("cfg.%s" % p) 
                if not old_path.startswith("/"): 
                    new_path = basedir + "/" + old_path
                else:
                    new_path = old_path
                if not os.path.isfile(new_path): 
                    log.warn("File %s does not exist" % new_path) 

                exec("cfg.%s = '%s'" % (p, new_path))
                #log.debug("Updated path from %s to %s " % \
                #              (old_path, eval("cfg.%s" % p)))
            except: 
                traceback.print_exc() 
                log.error("Could not update the path for cfg.%s" % p)
                pass
            
            # Treat the xsd paths specially. They are relative to the 
            # package
            xsd_paths = ['common.request_xsd', 'common.response_xsd']
            this_dir = os.path.dirname(os.path.realpath(__file__))
            exec("cfg.common.request_xsd='%s/xsd/uid-auth-request.xsd'" % \
                     this_dir)
            exec("cfg.common.response_xsd='%s/xsd/uid-auth-response.xsd'" % \
                     this_dir)
            #log.debug("request_xsd path is %s " % cfg.common.request_xsd)
            #log.debug("response_xsd path is %s " % cfg.common.response_xsd)

        return

    def update_config(self): 
        """
        Process each element of the command line and generate a target
        configuration.
        """

        logging.basicConfig() 
        usage = "usage: %prog [options] [<attrib=value> <attrib=value>...]\n" \
            + self._summary
        
        parser = OptionParser(usage=usage)
        
        if self._cfg == None: 
            default_config_file = "fixtures/auth.cfg"
        else: 
            default_config_file = self._cfg

        #=> Set the help text and other command line options. 
        parser.add_option("-c", "--config",
                          action="store", type="string", dest="config_file",
                          default=default_config_file,
                          help="Specify the input configuration file. " + 
                          "(default: %s)" % default_config_file,
                          metavar="FILE")
        parser.add_option("--show-example-config",
                          action="callback", callback=self.show_example_config, 
                          help="Sample configuration file")

        defaults = {
            'data': 'request_demo',
            'request': 'request_demo',
            'response': 'response_validate',
            'crypt': 'crypt_test',
            'signature': 'signature_default',
            'validate': 'validate_xml_only',
            'batch': 'batch_default',
            'unknown': 'unknown_default'
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
        log.debug("Setting request configuration to %s " % \
                     (eval("options.%s" % self._name)))
        cmd = "cfg.%s=cfg[options.%s]" %  (self._name, self._name) 
        exec(cmd) 
        
        # => Update the paths 
        if options.config_file.startswith('/'):
            config_path = options.config_file 
        else: 
            config_path = os.path.realpath(options.config_file)
        cfg['common']['dir'] = os.path.dirname(config_path)
        self.update_paths(cfg) 

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
            else: 
                cmd = "cfg.%s=\'%s\'" % (k, v)
                exec(cmd) 
                cmd = "cfg.%s" % k 
                log.debug("Updated conf var %s to %s \n" % (cmd, eval(cmd)))
                
        # Turn some strings in objects
        cfg.common.loglevel = eval("logging.%s" % cfg.common.loglevel)
        if (cfg.validate.signed):
            cfg.validate.signed = eval("%s" % cfg.validate.signed)

        log.debug("Final configuration:\n%s" % cfg)
        return cfg 

if __name__ == "__main__": 
    name = "request" 
    summary = "Issues authentication requests to the server" 
    
    logging.getLogger().setLevel(logging.DEBUG) 
    logging.basicConfig()#filename="execution.log") 
    c = AuthConfig(name, summary)
    cfg = c.update_config()



