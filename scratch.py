'''
Summary:
    This script will generate a report file based on the A10 Health Check. This sciprt is only meant to run every
    command as found in the health check.

    Eventual plans will be to make accessments based on the generated report, however, today the report must be
    reviewed by a qualified engineer manually.

Requires:
    - Python 3.x
    - aXAPI v3
    - ACOS 4.0 or higher

Revisions:
    - 0.1 - initial script generation by A10 engineers: Brandon Marrow, Terry Jones

'''
#!/usr/bin/env python

__version__ = '0.1'
__author__ = 'A10 Networks'

import argparse
import requests
from requests.exceptions import HTTPError
import json
import urllib3
import logging
import datetime

parser = argparse.ArgumentParser(description='Running this script will issue whatever commands are presented to this script.  All commands are issued from configuration mode.')
devices = parser.add_mutually_exclusive_group()
devices.add_argument('-d', '--device', default='192.168.0.152',help='A10 device hostname or IP address. Multiple devices may be included seperated by a comma.')
parser.add_argument('-p', '--password', default='a10', help='user password')
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
        device.set_logging_env()
        token = device.auth()

        ##################################################################################
        # Capture & Save Configurations
        ##################################################################################
        # COMMENTS:
        get_startup_cfg = False
        if get_startup_cfg == False:
            print("Skipping startup-config")
        else:
            device.build_section_header("RUNNING CONFIGURATION")
            run = device.get_running_configs()
            print(run)

        # COMMENTS: Run to collect the running-confg with all partitions
        get_running_cfg = False
        if get_running_cfg == False:
            print("Skipping running-config")
        else:
            device.build_section_header("ALL PARTITIONS STARTUP CONFIG")
            start = device.get_startup_configs()
            print(start)

        # COMMENTS: Run to collect json-config
        get_json_cfg = False
        if get_json_cfg == False:
            print("Skipping JSON config")
        else:
            device.build_section_header("JSON CONFIG")
            json_cfg = device.get_json_config()
            print(json_cfg)

        # REDUNDANCY CHECK: VCS
        # COMMENTS: Run all vcs cmds here for shared partition only
        # TODO: Add in code to check if vcs is configured. Can use vcs/action to check for enable
        '''
        a10-url:/axapi/v3/vcs/action
        {
          "action": {
            "action":"enable",
            "uuid":"5c122548-0b98-11e8-8bfd-525400350b47"
          }
        }
        '''
        run_vcs = False
        if run_vcs == False:
            print("Skipping vcs")
        else:
            device.build_section_header("VCS: /vcs/")
            images, summary = device.get_vcs()
            print("a10-url: /vcs/images/")
            print(images.content)
            print("a10-url: /vcs/summary")
            print(summary.content)

        # REDUNDANCY CHECK: VRRP-A
        # COMMENTS: Run all vrrp-a cmds here for shared partition only
        # TODO: Add in code to check if vrrp-a is configured. Can use vrrp-a common to check for enable
        '''
        a10-url:/axapi/v3/vrrp-a/common
        {
          "common": {
            "device-id":2,
            "set-id":5,
            "action":"enable",
            "uuid":"d2511e70-f2a0-11e5-b98f-5254000ebcf2"
          }
        }
        '''
        run_vrrpa = False
        if run_vrrpa == False:
            print("Skipping vrrp-a")
        else:
            device.build_section_header("VRRP-A: /shared/vrrp-a/:")
            vrrpa,detail,common,stats=device.get_vrrpa()
            print("a10-url /vrrp-a/: ")
            print(vrrpa)
            print("a10-url /vrrp-a/detail/: ")
            print(detail)
            print("a10-url /vrrp-a/common/: ")
            print(common)
            print("a10-url /vrrp-a/state/stats/: ")
            print(stats)

        # REDUNDANCY CHECK: VRRP-A PARTITIONS
        # COMMENTS: Run all cmds for all paritions
        # TODO: Add some code to check for vrrp-a before running cmds. Skip if no vrrp-a.
        run_vrrpa_partitions = False
        if run_vrrpa_partitions == False:
            print("Skipping partitions.")
        else:
            partitions = device.get_partition_list()
            for part in partitions:
                device.build_section_header(part)
                device.change_partition(part)
                print(device.get_json_config())
                device.build_section_header("/"+part+"/vrrp-a")
                vrrpa, detail, common, stats = device.get_vrrpa()
                print("a10-url /vrrp-a/: ")
                print(vrrpa)
                print("a10-url /vrrp-a/detail/: ")
                print(detail)
                print("a10-url /vrrp-a/common/: ")
                print(common)
                print("a10-url /vrrp-a/state/stats/: ")
                print(stats)

        ##################################################################################
        # Health Check
        ##################################################################################



        ##################################################################################
        # Interface/Trunk/Vlan Check
        ##################################################################################


        ##################################################################################
        # System Resources
        ##################################################################################



        ##################################################################################
        # Sessions Check
        ##################################################################################



        ##################################################################################
        # System Errors
        ##################################################################################



        ##################################################################################
        # Health Monitor Status
        ##################################################################################




        ##################################################################################
        # Performance Data
        ##################################################################################



        ##################################################################################
        # Application Services
        ##################################################################################



        ##################################################################################
        # Monitoring Review
        ##################################################################################



        ##################################################################################
        # Security Check
        ##################################################################################



        ##################################################################################
        # Version Check
        ##################################################################################



        ##################################################################################
        # Logoff AxAPI session
        ##################################################################################
        # COMMENTS: Always run logoff to ensure proper clean-up. If sessions are not closed, the login users
        # will be exceeded and the script can fail due to the maximum number of logins exceeded
        device.auth_logoff(token)

# Class for making all device calls using AxAPI v3.0
class Acos(object):
    def __init__(self, device, username, password):
        self.device = device
        self.username = username
        self.password = password
        self.base_url = 'http://' + device + '/axapi/v3/'
        self.headers = {'content-type': 'application/json'}
        self.run_config_with_def_all_parts = ''
        self.start_config_all_parts = ''
        self.run_json_config = ''

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
        return auth_token

    def auth_logoff(self,token):
        """authenticates and retrives the auth token for the A10 device"""

        self.logger.debug('Logging Off to clean up session.')
        self.headers['Authorization'] = 'A10 ' + token

        try:
            log_off = self.axapi_call('logoff', 'POST')
            logoff_response = log_off.content
            print("Token: ", token, "Logoff Response", logoff_response)
        except:
            self.logger.error("Error logging off of session")
        else:
            self.logger.debug('Logoff successful')

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

    def get_startup_configs(self):
        """Returns the startup configuration for an A10 device. Uses cli-deploy method."""
        self.start_config_all_parts = self.clideploy(['show startup-config all-partitions'])
        return self.start_config_all_parts.content

    def get_running_configs(self):
        """Returns the running configuration for an A10 device. Uses cli-deploy method."""
        self.run_config_with_def_all_parts = self.clideploy(['show running with-default partition-config all'])
        return bytes.decode(self.run_config_with_def_all_parts.content)

    def get_json_config(self):
        """Returns the json configuration for an A10 device. Uses cli-deploy method."""
        self.run_json_config = (self.clideploy(['show json-config']))
        return self.run_json_config.content

    def build_section_header(self, section):
        """prints section headers"""
        print('{:*^100s}'.format(''))
        print('{:*^100s}'.format(section))
        print('{:*^100s}'.format(''))
        print('')
        print('')

    def get_partition_list(self):
        """gets a list of all the partition names"""
        partitions =[]
        self.partition_list = self.axapi_call('partition', 'GET').content
        parsed_json = json.loads(self.partition_list)
        for item in parsed_json['partition-list']:
            partitions.append(item["partition-name"])
        return partitions

    def get_partition_config(self, partition):
        """gets the configuration for a particular partition"""
        change_partition = self.axapi_call('DMZ', 'GET')
        partition_config = self.axapi_call('/running-config', 'GET')
        print(partition_config.content)

    def change_partition(self,partition):
        try:
            set_partition = self.axapi_call('active-partition/' + partition, 'POST')
            print("Status code for change_partition: ", set_partition.status_code)
        except HTTPError:
            logging.debug('Issue changing partition to ',partition)
        else:
            print(partition,' partition response: ', set_partition.content)
            logging.debug('AxAPI changed to shared partition')

    def set_shared_partition(self):
        """Set AxAPI back to default (shared) partition)"""
        try:
            set_partition = self.axapi_call('shared', 'GET')
        except:
            logging.debug('Issue changing partition')
        else:
            print('shared partition response: ', set_partition.content)
            logging.debug('AxAPI changed to shared partition')

    def get_vrrpa(self):
        """Return information on vrrp-a. Will run calls for:
        show vrrp-a
        show vrrp-a detail
        show vrrp-a common
        show vrrp-a state stats
        """
        self.vrrpa = self.axapi_call('vrrp-a', 'GET').content
        self.vrrpa_detail = (self.clideploy(['show vrrp-a detail']))
        self.vrrpa_common = self.axapi_call('vrrp-a/common/', 'GET').content
        self.vrrpa_state_stats= self.axapi_call('vrrp-a/state/stats', 'GET').content

        return self.vrrpa,self.vrrpa_detail.content,self.vrrpa_common,self.vrrpa_state_stats

    def get_vcs(self):
        """Return the vcs information for the following cmds:
        show vcs images
        show vcs summary
        """
        self.vcs_images = (self.clideploy(['show vcs images']))
        print("vcs images: ")
        print(self.vcs_images.content)
        self.vcs_stat = (self.clideploy(['show vcs summary']))
        print("vcs summary: ")
        print(vcs_stat.content)

        return self.vcs_images,self.vcs_stat

    def memory(self):
        '''
        show memory
        '''
        return True

    def hd(self):
        '''
        show hardware
        show disk
        show slb hw-compression
        show environment
        '''
        return True

    def eth_ints(self):
        '''
        This section will run the following cmds for ethernet or fiber interfaces
        show interfaces transceiver (if using fiber)
        show interfaces
        show vlans
        '''
        return True

    def trunk_ints(self):
        '''
        This section will run the following cmds for trunk interfaces
        show trunk
        show lacp counter
        show lacp trunk detail
        '''
        return True

    def get_vlans(self):
        '''
        This section will run the following cmds for vlans
        show vlans
        '''
        return True

    def system_resources_info(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show system resource-usage
        show slb resource-usage
        show resource-accounting all-partitions summary
        show resource-accounting global
        show resource-accounting resource-type app-resources
        show resource-accounting resource-type network-resources

        '''
        return True

    def cpu_info(self):
        '''
        This section will run the following cmds for the CPU
        show cpu
        show cpu overall
        show cpu history
        '''
        return True

    def session_info(self):
        '''
        This section will run the following cmds for the sessions section.

        show session
        show ip route
        show ip stats
        show ip anomaly-drop statistics
        show slb switch | i TCP
        show slb tcp stack
        show slb switch | i UDP
        show slb ssl error
        show slb ssl stats
        show slb l4 detail
        show resource-accounting resource-type system-resources
        '''
        return True

    def errors_check(self):
        '''
        This section will run the following cmds for the systems error section.

        show log | i Error
        show errors (available in some ACOS versions)
        '''
        return True

    def health_monitor_status(self):
        '''
        This section will run the following cmds for the health monitor status.

        show health stat
        #TODO: will need to check for downed resources, get a list of down-reasons, then run cmd
        show health down-reason <##>
        '''
        return True

    def performance(self):
        '''
        This section will run the following cmds for the performance section.

        #TODO: this cmd will require a loop and execute for t seconds, where t = 60 (but configurable).
        show slb performance
        '''
        return True

    def monitoring_info(self):
        '''
        This section will run the following cmds for monitoring.

        show logging
        '''
        return True

    def security_check(self):
        '''
        This section will run the following cmds for the security check

        show management
	    show slb conn-rate-limit src-ip statistics
	    show ip anomaly-drop statistics
        '''
        return True

    def version_check(self):
        '''
        This section will run the following cmds for the version check.

        show version
	    show bootimage
        '''
        return True

# Not sure if needed as shouldn't get response errors, but could write in error handler just in case.
class AxAPI_HTTP_RC_Exception(Exception):
    def __init__(self, error_code, error_msg):
        self.error_code = error_code
        self.error_msg = error_msg
        if response.status_code == 401:
            raise MyException(401, "401 - Unauthorized")
        elif response.status_code == 404:
            raise MyException(404, "404 - URI Not Found")
        elif response.status_code == 503:
            raise MyException(503, "503 - Service Unavailable")
    return True


if __name__ == '__main__':
    main()