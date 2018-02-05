#!/usr/bin/env python
#
#
# Requires:
#   - Python 3.x
#   - aXAPI V3
#   - ACOS 3.0 or higher
#

import argparse
import requests
import json
import urllib3
import logging
import datetime


parser = argparse.ArgumentParser(description='Running this script will issue whatever commands are presented to this script.  All commands are issued from configuration mode.')

devices = parser.add_mutually_exclusive_group()

devices.add_argument('-d', '--device', default='', help='A10 device hostname or IP address. Multiple devices may be included seperated by a comma.')
parser.add_argument('-p', '--password', help='user password')
parser.add_argument('-u', '--username', default='admin', help='username (default: admin)')
parser.add_argument('-v', '--verbose', default=0, action='count', help='Enable verbose detail')

try:
    args = parser.parse_args()
    devices = args.device.split(',')
    password = args.password
    username = args.username
    verbose = args.verbose

except Exception as e:
    print(e)

# set the default logging format
logging.basicConfig(format="%(name)s: %(levelname)s: %(message)s")





def main():
    urllib3.disable_warnings()
    for device in devices:
        device = Acos(device, username, password)

class Acos(object):
    def __init__(self, device, username, password ):
        self.device = device
        self.username = username
        self.password = password
        self.base_url = 'https://' + device + '/axapi/v3/'
        self.headers = {'content-type': 'application/json'}
        self.run_config_with_def_all_parts = ''
        self.start_config_all_parts = ''
        self.set_logging_env()
        self.auth()
        self.get_configs()
        self.show_configs()


    def set_logging_env(self):
        """Set logging environment for the device"""

        dt = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

        # build the logger object
        self.logger = logging.getLogger(self.device)

        logging.basicConfig(format="%(name)s: %(levelname)s: %(message)s")

        # set your verbosity levels
        if verbose == 0:
            self.logger.setLevel(logging.ERROR)

        elif verbose == 1:
            self.logger.setLevel(logging.INFO)

        elif verbose >= 2:
            self.logger.setLevel(logging.DEBUG)


        # set logging message in the following levels like so:
        # self.logger.error('this is an error')
        # self.logger.info('this is some info')
        # self.logger.debug('this is debug')


    def auth(self):
        """authenticates and retrives the auth token for the A10 device"""

        self.logger.debug('Entering the auth method')
        payload = {"credentials": {"username": self.username, "password": self.password}}
        authorization = self.axapi_call('auth', 'POST', payload)
        auth_token = authorization.json()['authresponse']['signature']
        self.headers['Authorization'] = 'A10 ' + auth_token
        self.logger.debug('Exiting the auth method')

    def axapi_call(self, module, method, payload=''):
        """axapi structure for making all api requests"""

        self.logger.debug('Entering the axapi_call method')
        url = self.base_url + module
        if method == 'GET':
            r = requests.get(url, headers=self.headers, verify=False)
        elif method == 'POST':
            r = requests.post(url, data=json.dumps(payload), headers=self.headers, verify=False)
        if verbose:
            print(r.content)
        self.logger.debug('Exiting the axapi_call method')
        return r

    def clideploy(self, commands):
        """clideploy just in case you need it"""

        self.logger.debug('Entering the clideploy method')
        payload = {'CommandList': commands}
        r = self.axapi_call('clideploy', 'POST', payload)
        self.logger.debug('Exiting the clideploy method')
        return r

    def get_configs(self):
        """gets the running and startup configs"""
        self.run_config_with_def_all_parts = self.clideploy(['show running with-default partition-config all'])
        self.start_config_all_parts = self.clideploy(['show startup-config all-partitions'])

    def show_configs(self):
        """prints the running and startup configs"""
        print('******************************************************************************************************')
        print('***************************CURRENT RUNNING CONFIGURATION FOR ALL PARTITIONS***************************')
        print('********************************CONFIG INCLUDES DEFAULT SETTINGS**************************************')
        print(bytes.decode(self.run_config_with_def_all_parts.content))
        print('')
        print('')
        print('******************************************************************************************************')
        print('***************************CURRENT STARTUP CONFIGURATION FOR ALL PARTITIONS***************************')
        print(bytes.decode(self.start_config_all_parts.content))


if __name__ == '__main__':
    main()