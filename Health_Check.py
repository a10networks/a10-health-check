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
devices.add_argument('-d', '--device', default='10.0.1.222', help='A10 device hostname or IP address. Multiple devices may be included seperated by a comma.')
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
        device.auth()
        device.get_partition_list()

        for partition in device.partitions:
            device.change_parition(partition)
            device.get_slb_servers(partition)
            device.get_slb_service_groups(partition)
            device.get_slb_virtual_servers(partition)

            #need to generate a list of server names then iterate through them
            #once for oper data and another for stat data

            #need to generate a list of service-group names then iterate through them
            #once for oper data and another for stat data

            #need to generate a list of virtual-server names then iterate through them
            #once for oper data and another for stat data

        #device.get_configs()

        # needs to be flushed out
        # thought was, if VRRP-A isn't running skip the VRRP-A checks
        # maybe that gets moved/tabled for the parser script
        #device.get_vrrpa()
        #if not device.vrrpa_status_active:
        #    device.parse_vrrpa_details()

class Acos(object):
    def __init__(self, device, username, password):
        self.device = device
        self.username = username
        self.password = password
        self.base_url = 'https://' + device + '/axapi/v3/'
        self.headers = {'content-type': 'application/json'}
        self.run_config_with_def_all_parts = ''
        self.start_config_all_parts = ''
        self.partitions = []

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

        # currently is decoding and printing as text, maybe allow it as just the JSON response?
        self.run_config_with_def_all_parts = self.clideploy(['show running with-default partition-config all'])
        self.start_config_all_parts = self.clideploy(['show startup-config all-partitions'])

        self.build_section_header('ALL PARTITIONS RUNNING CONFIG')
        print(bytes.decode(self.run_config_with_def_all_parts.content))
        self.build_section_header('ALL PARTITIONS STARTUP CONFIG')
        print(bytes.decode(self.start_config_all_parts.content))

    def build_section_header(self, section):
        """prints section headers"""

        # prints a line 100 characters long taking into account the section name
        # I know, fancy right?
        print('{:*^100s}'.format(''))
        print('{:*^100s}'.format(section))
        print('{:*^100s}'.format(''))
        print('')
        print('')

############
############
    #Terry everything below here was just inital thoughts, update as needed


    def get_vrrpa(self):
        self.vrrpa = self.axapi_call('vrrp-a', 'GET').content
        self.vrrpa_json = json.loads(self.vrrpa, encoding=bytes)

        try:
            self.vrrpa_json['vrrp-a']['common']['action'] == 'enable'
            self.vrrpa_status_active = True
            #print(json.dumps(self.vrrpa_json, indent=4, sort_keys=True))
        except:
            self.vrrpa_status_active = False
            self.logger.error("VRRP-A is not enabled")

        else:
            self.vrrpa_status_active = False

    def parse_vrrpa_details(self):
        pass

    def get_partition_list(self):
        """gets a list of all the partition names"""
        self.partition_list = json.loads(self.axapi_call('partition', 'GET').content, encoding=bytes)

        for partition in self.partition_list['partition-list']:
            name = partition.get('partition-name')
            self.partitions.append(name)

    def change_parition(self, partition):
        """changes the active partition"""
        payload = {'active-partition': {'curr_part_name': partition}}
        self.axapi_call('active-partition', 'POST', payload)

    def get_slb_servers(self, partition='shared'):
        """gets a list of all slb servers"""

        self.build_section_header('SLB SERVERS for partition ' + partition)

        servers_list = self.axapi_call('slb/server', 'GET')
        servers_list = servers_list.content.decode()
        print(servers_list)

    def get_slb_server_stats(self, server, partition='shared'):
        """gets operational stats for a slb server"""

        self.build_section_header('OPERATIONAL DATA for slb server ' + server)

        slb_server_stats = self.axapi_call('slb/server/' + server + '/stats', 'GET')
        slb_server_stats = slb_server_stats.content.decode()
        print(slb_server_stats)

    def get_slb_service_groups(self, partition='shared'):
        """gets a list of all service-groups"""

        self.build_section_header('SLB SERVICE_GROUP for partition ' + partition)

        service_group_list = self.axapi_call('slb/service-group', 'GET')
        service_group_list = service_group_list.content.decode()
        print(service_group_list)

    def get_slb_virtual_servers(self, partition='shared'):
        """gets a list of all virtual-servers"""

        self.build_section_header('SLB VIRTUAL-SERVERS for partition ' + partition)

        virtual_server_list = self.axapi_call('slb/virtual-server', 'GET')
        virtual_server_list = virtual_server_list.content.decode()
        print(virtual_server_list)


    def iterate_partition_configs(self):
        """iterates through each of the partitions for their configs"""
        for partition in self.partition_list['partition-list']:
            part_name = partition['a10-url'].split('/')[-1]
            self.get_partition_config(part_name)

    def get_partition_config(self, partition):
        """gets the configuration for a particular partition"""
        partition_config = self.axapi_call('partition/' + partition + '/running-config', 'GET')
        print(partition_config.content)

if __name__ == '__main__':
    main()