#!/usr/bin/env python3

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
    - 0.1 - initial script generation by A10 engineers: Brandon Marlow, Terry Jones

'''
__version__ = '0.1'
__author__ = 'A10 Networks'

import argparse
import requests
from requests.exceptions import HTTPError
import json
import urllib3
import logging
import datetime
import ast

parser = argparse.ArgumentParser(
    description='Running this script will issue whatever commands are presented to this script.  All commands are issued from configuration mode.')
devices = parser.add_mutually_exclusive_group()
devices.add_argument('-d', '--device', default='192.168.0.152',
                     help='A10 device hostname or IP address. Multiple devices may be included seperated by a comma.')
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

# verbose = 1

# set the default logging format
logging.basicConfig(format="%(name)s: %(levelname)s: %(message)s")


def main():
    urllib3.disable_warnings()
    for device in devices:
        device = Acos(device, username, password)
        device.set_logging_env()
        token = device.auth()

        # get a list of partitions (we will iterate over it multiple times later on
        device.partitions = device.get_partition_list()

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
            vrrpa, detail, common, stats = device.get_vrrpa()
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
                device.build_section_header("/" + part + "/vrrp-a")
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

        run_health_check = True
        if run_health_check == False:
            print("Skipping Health Check session.")
        else:
            device.build_section_header("Health Check: /memory/:")
            mem_data = device.get_memory()
            print("a10-url /memory/: ")
            print(mem_data)

        ##################################################################################
        # Interface/Trunk/Vlan Check
        ##################################################################################


        # TODO: need to maybe to check to verify if transceivers are present
        # show interfaces transceiver


        ##################################################################################
        # System Resources
        ##################################################################################

        ##################################################################################
        # Sessions Check
        ##################################################################################


        # TODO: Parse output for only TCP entries
        # show slb switch | i TCP


        # TODO: Parse output for only TCP entries
        # show slb switch | i TCP

        ##################################################################################
        # System Errors
        ##################################################################################

        ##################################################################################
        # Health Monitor Status
        ##################################################################################

        # TODO: will need to check for downed resources, get a list of down-reasons, then run cmd
        # show health down-reason <##>

        ##################################################################################
        # Performance Data
        ##################################################################################

        # TODO: this cmd will require a loop and execute for t seconds, where t = 60 (but configurable).


        ##################################################################################
        # Application Services
        ##################################################################################

        run_application_stats = False
        if run_application_stats == False:
            print("Skipping appplication stats.")
        else:

            device.build_section_header('APPLICATION SERVICES CHECK')
            # iterate through each partition
            for partition in device.partitions:

                # change to the first partition
                device.change_partition(partition)
                device.build_section_header('PARTITION: ' + partition)
                # instantiate empty list of servers
                servers = []
                # get json list of servers
                slb_servers = device.get_slb_servers()

                # for each server in the list (if isn't empty) add the name as a value
                if slb_servers:
                    for server in slb_servers['server-list']:
                        servers.append(server['name'])

                    # for each named server print a header then the stat information
                    for server in servers:
                        server_stats = device.get_slb_server_stats(server)
                        device.build_section_header('Stats for partition: ' + partition + '::SLB SERVER ' + server)
                        print(server_stats)

                # instatiate an empty list of service-groups
                service_groups = []
                # get the json list of service-groups
                slb_service_groups = device.get_slb_service_groups()

                # for each service-group in the list (if it isn't empty) add the name as a value
                if slb_service_groups:
                    for service_group in slb_service_groups['service-group-list']:
                        service_groups.append(service_group['name'])

                    # for each named service-group print a header then the stat information
                    for service_group in service_groups:
                        service_group_stats = device.get_slb_service_group_stats(service_group)
                        device.build_section_header(
                            'Stats for partition: ' + partition + '::SLB SERVICE-GROUP ' + service_group)
                        print(service_group_stats)

                # instatiate an empty list of virtual-servers
                virtual_servers = []
                # get teh json list of virtual-servers
                slb_virtual_servers = device.get_slb_virtual_servers()

                # for each virtual-server in the list (if it isn't empty) add the name as a value
                if slb_virtual_servers:
                    for virtual_server in slb_virtual_servers['virtual-server-list']:
                        virtual_servers.append(virtual_server['name'])

                    # for each named virtual-server print a header then the stat information
                    for virtual_server in virtual_servers:
                        virtual_server_stats = device.get_slb_virtual_server_stats(virtual_server)
                        device.build_section_header(
                            'Stats for partition: ' + partition + '::SLB VIRTUAL-SERVER ' + virtual_server)
                        print(virtual_server_stats)

            device.change_partition('shared')

        ##################################################################################
        # Monitoring Review
        ##################################################################################
        run_monitoring_check = False
        if run_monitoring_check == False:
            print("Skipping monitoring check")
        else:
            device.build_section_header('MONITORING REVIEW')
            logging_data = device.get_logging_data()
            print(logging_data)

        ##################################################################################
        # Security Check
        ##################################################################################

        run_security_check = False
        if run_security_check == False:
            print("Skipping security check.")
        else:
            device.build_section_header('SECURITY CHECK')
            management = device.get_management_services()
            conn_limit_data = device.get_slb_conn_rate_limit_data()
            ip_anomaly = device.get_ip_anomaly_drop()

            print(management)
            # if there is no conn_limit_data a blank line will print
            print(conn_limit_data)
            print(ip_anomaly)

        ##################################################################################
        # Version Check
        ##################################################################################
        run_version_check = False
        if run_version_check == False:
            print("Skipping version check.")
        else:
            device.build_section_header('VERSION/BOOTIMAGE CHECK')
            version = device.get_version()
            bootimage = device.get_bootimage()

            print(version)
            print(bootimage)

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
        """authenticates and retrieves the auth token for the A10 device"""

        self.logger.debug('Entering the auth method')
        payload = {"credentials": {"username": self.username, "password": self.password}}
        authorization = self.axapi_call('auth', 'POST', payload)
        auth_token = authorization.json()['authresponse']['signature']
        self.headers['Authorization'] = 'A10 ' + auth_token
        self.logger.debug('Exiting the auth method')
        return auth_token

    def auth_logoff(self, token):
        """authenticates and retrives the auth token for the A10 device"""

        self.logger.debug('Logging Off to clean up session.')
        self.headers['Authorization'] = 'A10 ' + token

        try:
            log_off = self.axapi_call('logoff', 'POST')
            logoff_response = log_off.content.decode()
            # print("Token: ", token, "Logoff Response\n", logoff_response)
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
        self.logger.debug('Exiting get_startup_configs method')
        return self.start_config_all_parts.content

    def get_running_configs(self):
        """Returns the running configuration for an A10 device. Uses cli-deploy method."""
        self.run_config_with_def_all_parts = self.clideploy(['show running with-default partition-config all'])
        self.logger.debug('Exiting get_running_config method')
        return bytes.decode(self.run_config_with_def_all_parts.content)

    def get_json_config(self):
        """Returns the json configuration for an A10 device. Uses cli-deploy method."""
        self.run_json_config = (self.clideploy(['show json-config']))
        self.logger.debug('Exiting get_json_config method')
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
        # instatiate list with shared partition as it is implied and not returned by the REST endpoint
        partitions = ['shared']
        partition_list = self.axapi_call('partition', 'GET').content.decode()
        parsed_json = json.loads(partition_list)
        for item in parsed_json['partition-list']:
            partitions.append(item["partition-name"])
        return partitions

    def get_partition_config(self, partition):
        """gets the configuration for a particular partition"""
        self.axapi_call(partition, 'GET')
        partition_config = self.axapi_call('/running-config', 'GET')
        self.logger.debug('Exiting get_partition_config method')
        return partition_config

    def change_partition(self, partition):
        try:
            payload = {'active-partition': {'curr_part_name': partition}}
            set_partition = self.axapi_call('active-partition/' + partition, 'POST', payload)
            # print("Status code for change_partition: ", set_partition.status_code)
        except HTTPError:
            logging.debug('Issue changing partition to ', partition)
        else:
            # print(partition,' partition response: ', set_partition.content)
            logging.debug('AxAPI changed to shared partition')

    def get_vrrpa(self):
        """Return information on vrrp-a. Will run calls for:
        show vrrp-a
        show vrrp-a detail
        show vrrp-a common
        show vrrp-a state stats
        """
        self.vrrpa = self.axapi_call('vrrp-a', 'GET').content.decode()
        self.vrrpa_detail = (self.clideploy(['show vrrp-a detail'])).content.decode()
        self.vrrpa_common = self.axapi_call('vrrp-a/common/', 'GET').content.decode()
        self.vrrpa_state_stats = self.axapi_call('vrrp-a/state/stats', 'GET').content.decode()
        self.logger.debug('Exiting get_vrrpa method')
        return vrrpa, vrrpa_detail.content, vrrpa_common, vrrpa_state_stats

    def get_vcs_images(self):
        """Return the vcs information for the following cmds:

        show vcs images
        show vcs summary
        """
        self.logger.debug('Entering get_vcs_images method')
        vcs_images = (self.clideploy(['show vcs images']))
        vcs_summary = (self.clideploy(['show vcs summary']))
        self.logger.debug('Exiting get_vcs_images method')
        return vcs_images, vcs_summary

    def get_slb_servers(self):
        """gets a list of all slb servers"""

        self.logger.debug('Entering get_slb_servers method')
        servers_list = self.axapi_call('slb/server', 'GET').content.decode()

        if servers_list:
            servers_list = json.loads(servers_list)
        self.logger.info(servers_list)
        self.logger.debug('Exiting get_slb_servers method')
        return servers_list

    def get_slb_service_groups(self):
        """gets a list of all service-groups"""

        self.logger.debug('Entering get_slb_service_groups method')
        service_group_list = self.axapi_call('slb/service-group', 'GET').content.decode()

        if service_group_list:
            service_group_list = json.loads(service_group_list)
        self.logger.info(service_group_list)
        self.logger.debug('Exiting get_slb_service_groups method')
        return service_group_list

    def get_slb_virtual_servers(self):
        """gets a list of all virtual-servers"""

        self.logger.debug('Entering get_slb_virtual_servers method')
        virtual_server_list = self.axapi_call('slb/virtual-server', 'GET').content.decode()

        if virtual_server_list:
            virtual_server_list = json.loads(virtual_server_list)
        self.logger.info(virtual_server_list)
        self.logger.debug('Exiting get_slb_virtual_servers method')
        return virtual_server_list

    def get_slb_server_stats(self, server):
        """gets operational stats for a slb server"""

        self.logger.debug('Entering get_slb_server_stats method')
        slb_server_stats = self.axapi_call('slb/server/' + server + '/stats', 'GET').content.decode()
        self.logger.info(slb_server_stats)
        self.logger.debug('Exiting get_slb_server_stats method')
        return slb_server_stats

    def get_slb_service_group_stats(self, service_group):
        """get operational stats for a service-group"""

        self.logger.debug('Entering get_slb_service_group_stats method')
        service_group_stats = self.axapi_call('slb/service-group/' + service_group + '/stats', 'GET')
        service_group_stats = service_group_stats.content.decode()
        self.logger.info(service_group_stats)
        self.logger.debug('Exiting get_slb_service_group_stats method')
        return service_group_stats

    def get_slb_virtual_server_stats(self, virtual_server):
        """get operation stats for a virtual-server"""
        self.logger.debug('Entering get_slb_service_group_stats method')
        virtual_server_stats = self.axapi_call('slb/virtual-server/' + virtual_server + '/stats', 'GET')
        virtual_server_stats = virtual_server_stats.content.decode()
        self.logger.info(virtual_server_stats)
        self.logger.debug('Exiting get_slb_service_group_stats method')
        return virtual_server_stats

    def get_slb_server_oper(self, server):
        """gets operational status for a server"""
        self.logger.debug('Entering get_slb_server_oper method')
        server_oper = self.axapi_call('slb/server/' + server + '/oper', 'GET')
        server_oper = server_oper.content.decode()
        self.logger.info(server_oper)
        self.logger.debug('Exiting get_slb_server_oper method')
        return server_oper

    def get_slb_service_group_oper(self, service_group):
        """gets operational status for a service-group"""
        self.logger.debug('Entering get_slb_service_group_oper method')
        service_group_oper = self.axapi_call('slb/service-group/' + service_group + '/oper', 'GET')
        service_group_oper = service_group_oper.content.decode()
        self.logger.info(service_group_oper)
        self.logger.debug('Exiting get_slb_service_group_oper method')
        return service_group_oper

    def get_slb_virtual_server_oper(self, virtual_server):
        """gets operational status for a virtual_server"""
        self.logger.debug('Entering get_slb_virtual_server_oper method')
        virtual_server_oper = self.axapi_call('slb/virtual-server/' + virtual_server + '/oper', 'GET')
        virtual_server_oper = virtual_server_oper.content.decode()
        self.logger.info(virtual_server_oper)
        self.logger.debug('Exiting get_slb_virtual_server_oper method')
        return virtual_server_oper

    def get_memory(self):
        '''
        show memory
        '''
        self.logger.debug('Entering get_memory method')
        memory_info = self.axapi_call('system/memory/oper', 'GET').content.decode()
        self.logger.info(memory_info)
        self.logger.debug('Exiting get_memory method')
        return memory_info

    def get_system_oper(self):
        '''
        show oper
        '''
        self.logger.debug('Entering get_system_oper method')
        system_oper = self.axapi_call('system/oper/', 'GET').content.decode()
        self.logger.info(system_oper)
        self.logger.debug('Exiting get_system_oper method')
        return system_oper

    def get_health(self):
        '''
        show health monitor
        '''
        self.logger.debug('Entering get_health method')
        health_info = self.axapi_call('health/monitor', 'GET').content.decode()
        self.logger.info(health_info)
        self.logger.debug('Exiting get_health method')
        return health_info

    def get_health_stat(self):
        '''
        show health stat
        '''
        self.logger.debug('Entering get_health_stat method')
        # BROKEN schema::health_stat = self.axapi_call('health/stat', 'GET').content.decode()
        health_stat = self.clideploy(['show health stat'])
        self.logger.info(health_stat)
        self.logger.debug('Exiting get_health_stat method')
        return health_stat

    def get_hardware(self):
        '''
        show hardware
        '''
        self.logger.debug('Entering get_hardware method')
        hardware = self.axapi_call('system/hardware/oper', 'GET').content.decode()
        self.logger.info(hardware)
        self.logger.debug('Exiting get_hardware method')
        return hardware

    def get_disk(self):
        '''
        show disk
        '''
        self.logger.debug('Entering get_disk method')
        disk = self.axapi_call('hd/', 'GET').content.decode()
        self.logger.info(disk)
        self.logger.debug('Exiting get_disk method')
        return disk

    def get_slb_hw_compression(self):
        '''
        show slb hw-compression
        '''
        self.logger.debug('Entering get_slb_hw_compression method')
        slb_hw_compression = self.axapi_call('slb/hw-compress/stats', 'GET').content.decode()
        self.logger.info(slb_hw_compression)
        self.logger.debug('Exiting get_slb_hw_compression method')
        return slb_hw_compression

    def get_environment(self):
        '''
        Hardware only

        show environment
        '''
        self.logger.debug('Entering get_environment method')
        evironment = self.axapi_call('system/environment', 'GET').content.decode()
        self.logger.info(evironment)
        self.logger.debug('Exiting get_environment method')
        return evironment

    def get_interfaces_transceiver(self):
        '''
        This section will run the following cmds for fiber interfaces

        show interfaces transceiver
        '''
        self.logger.debug('Entering get_fiber_info method')
        # BROKEN schema::interfaces_transceiver = self.axapi_call('network/interface/transceiver', 'GET').content.decode()
        interfaces_transceiver = self.clideploy(['show interfaces transceiver'])
        self.logger.info(interfaces_transceiver)
        self.logger.debug('Exiting get_fiber_info method')
        return interfaces_transceiver

    def get_interface_ethernet(self):
        '''
        This section will run the following cmds for ethernet interfaces
        
        show interfaces
        '''
        self.logger.debug('Entering get_interface_ethernet method')
        interface_ethernet = self.axapi_call('interface/ethernet/stats', 'GET').content.decode()
        self.logger.info(interface_ethernet)
        self.logger.debug('Exiting get_interface_ethernet method')
        return interface_ethernet

    def get_trunk(self):
        '''
        This section will run the following cmds for trunk interfaces

        show trunk
        '''
        self.logger.debug('Entering get_trunk method')
        trunk = self.axapi_call('interface/trunk/stats', 'GET').content.decode()
        self.logger.info(trunk)
        self.logger.debug('Exiting get_trunk method')
        return trunk

    def get_lacp(self):
        '''
        This section will run the following cmds for trunk interfaces

        show lacp trunk detail
        '''
        self.logger.debug('Entering get_lacp_trunk_detail method')
        # BROKEN schmea::lacp = self.axapi_call('hd/', 'GET').content.decode()
        lacp_trunk_detail = self.clideploy(['show lacp trunk detail'])
        self.logger.info(lacp_trunk_detail)
        self.logger.debug('Exiting get_lacp_info method')
        return lacp_trunk_detail

    def get_lacp_counters(self):
        '''
        This section will run the following cmds for lacp counters
        show lacp counter
        '''
        self.logger.debug('Entering get_lacp_counters method')
        lacp_counters = self.axapi_call('network/lacp/stats', 'GET').content.decode()
        self.logger.info(lacp_counters)
        self.logger.debug('Exiting get_lacp_counters method')
        return lacp_counters

    def get_vlans(self):
        '''
        This section will run the following cmds for vlans
        show vlans
        '''
        self.logger.debug('Entering get_vlans method')
        vlans = self.axapi_call('network/vlan', 'GET').content.decode()
        self.logger.info(vlans)
        self.logger.debug('Exiting get_vlans method')
        return vlans

    def get_vlan_stats(self):
        '''
        This section will run the following cmds for vlans
        show vlan counters
        '''
        self.logger.debug('Entering get_vlan_stats method')
        vlan_stats = self.axapi_call('network/vlan/stats', 'GET').content.decode()
        self.logger.info(vlan_stats)
        self.logger.debug('Exiting get_vlan_stats method')
        return vlan_stats

    def get_system_resources_usage(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show system resource-usage
        '''
        self.logger.debug('Entering get_system_resources_usage method')
        system_resources_usage = self.axapi_call('system/resources-usage/oper', 'GET').content.decode()
        self.logger.info(system_resources_usage)
        self.logger.debug('Exiting get_system_resources_usage_info method')
        return system_resources_usage

    def get_slb_resources_usage(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show slb resource-usage
        '''
        self.logger.debug('Entering get_slb_resources_usage method')
        slb_resource_info = self.axapi_call('slb/resources-usage/oper', 'GET').content.decode()
        self.logger.info(slb_resource_info)
        self.logger.debug('Exiting get_slb_resources_usage method')
        return slb_resource_info

    def get_resources_acct_all_partitions(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show resource-accounting all-partitions summary
        '''
        self.logger.debug('Entering get_resources_acct_all_partitions method')
        # BROKEN schema::get_rescouce_acct_part_info = self.axapi_call('system/resource-accounting/', 'GET').content.decode()
        resources_acct_all_partitions = (self.clideploy(['show resource-accounting all-partitions summary']))
        self.logger.info(resources_acct_all_partitions)
        self.logger.debug('Exiting get_resources_acct_all_partitions method')
        return resources_acct_all_partitions

    def get_resource_acct_global(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show resource-accounting global
        '''
        self.logger.debug('Entering get_resource_acct_global method')
        resource_acct_global = self.axapi_call('system/resource-accounting/oper', 'GET').content.decode()
        self.logger.info(resource_acct_global)
        self.logger.debug('Exiting get_resource_acct_global method')
        return resource_acct_global

    def get_resource_acct_apps(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show resource-accounting resource-type app-resources
        '''
        self.logger.debug('Entering get_resource_acct_apps method')
        # BROKEN schema::resource_acct_apps_info = self.axapi_call('system/resource-accounting/', 'GET').content.decode()
        resource_acct_apps = (self.clideploy(['show resource-accounting resource-type app-resources']))
        self.logger.info(resource_acct_apps)
        self.logger.debug('Exiting get_resource_acct_apps method')
        return resource_acct_apps

    def get_resource_acct_ntwk(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show resource-accounting resource-type network-resources
        '''
        self.logger.debug('Entering get_resource_acct_ntwk method')
        # BROKEN schema::resource_acct_ntwk_info = self.axapi_call('system/resource-accounting/', 'GET').content.decode()
        resource_acct_ntwk = (self.clideploy(['show resource-accounting resource-type app-resources']))
        self.logger.info(resource_acct_ntwk)
        self.logger.debug('Exiting get_resource_acct_ntwk method')
        return resource_acct_ntwk

    def get_icmp_stats(self):
        '''
        This section will run the following cmds for the CPU

        show system icmp
        '''
        self.logger.debug('Entering get_icmp_stats method')
        get_icmp_stats = self.axapi_call('system/icmp/stats', 'GET').content.decode()
        self.logger.info(get_icmp_stats)
        self.logger.debug('Exiting get_icmp_stats method')
        return get_icmp_stats

    def get_cpu(self):
        '''
        This section will run the following cmds for the CPU

        show cpu
        '''
        self.logger.debug('Entering get_cpu method')
        # BROKEN schema::cpu_info = self.axapi_call('system/data-cpu/', 'GET').content.decode()
        cpu_info = (self.clideploy(['show cpu']))
        self.logger.info(cpu_info)
        self.logger.debug('Exiting get_cpu method')
        return cpu_info

    def get_cpu_load_sharing(self):
        '''
        This section will run the following cmds for the CPU

        show cpu
        '''
        self.logger.debug('Entering get_cpu_load_sharing method')
        cpu_load_sharing = self.axapi_call('system/cpu-load-sharing', 'GET').content.decode()
        self.logger.info(cpu_load_sharing)
        self.logger.debug('Exiting get_cpu_load_sharing method')
        return cpu_load_sharing

    def get_cpu_overall(self):
        '''
        This section will run the following cmd for the CPU

        show cpu overall
        '''
        self.logger.debug('Entering get_cpu_overall method')
        # BROKEN schema::cpu_overall_info = self.axapi_call('system/data-cpu/overall', 'GET').content.decode()
        cpu_overall_info = (self.clideploy(['show cpu overall']))
        self.logger.info(cpu_overall_info)
        self.logger.debug('Exiting get_cpu_overall method')
        return cpu_overall_info

    def get_cpu_history(self):
        '''
        This section will run the following cmd for the CPU

        show cpu history
        '''
        self.logger.debug('Entering get_cpu_history method')
        # BROKEN schema::cpu_history = self.axapi_call('system/data-cpu/', 'GET').content.decode()
        cpu_history = (self.clideploy(['show cpu history']))
        self.logger.info(cpu_history)
        self.logger.debug('Exiting get_cpu_history method')
        return cpu_history

    def get_session(self):
        '''
        This section will run the following cmds for the sessions section.

        show session
        '''
        self.logger.debug('Entering get_session method')
        # BROKEN schema::session_info = self.axapi_call('system/session/stats', 'GET').content.decode()
        session = (self.clideploy(['show session']))
        self.logger.info(session)
        self.logger.debug('Exiting get_session method')
        return session

    def get_ip_route(self):
        '''
        This section will run the following cmds for the sessions section.

        show ip route
        '''
        self.logger.debug('Entering get_ip_route method')
        # BROKEN schema::ip_route = self.axapi_call('hd/', 'GET').content.decode()
        ip_route = (self.clideploy(['show ip route']))
        self.logger.info(ip_route)
        self.logger.debug('Exiting get_ip_route method')
        return ip_route

    def get_ip_stats(self):
        '''
        This section will run the following cmds for the sessions section.

        show ip stats
        '''
        self.logger.debug('Entering get_ip_stats method')
        ip_stats = self.axapi_call('ip/stats', 'GET').content.decode()
        self.logger.info(ip_stats)
        self.logger.debug('Exiting get_ip_stats method')
        return ip_stats

    def get_slb_switch(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb switch
        '''
        self.logger.debug('Entering get_slb_switch method')
        slb_switch = self.axapi_call('slb/switch/stats', 'GET').content.decode()
        self.logger.info(slb_switch)
        self.logger.debug('Exiting get_slb_switch method')
        return slb_switch

    def get_slb_tcp_stack(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb tcp stack
        '''
        self.logger.debug('Entering get_slb_tcp_stack method')
        # BROKEN schema::get_session_info = self.axapi_call('hd/', 'GET').content.decode()
        slb_tcp_stack = (self.clideploy(['show slb tcp stack']))
        self.logger.info(slb_tcp_stack)
        self.logger.debug('Exiting get_slb_tcp_stack method')
        return slb_tcp_stack

    def get_system_bandwidth_stats(self):
        '''
        This function will return total input/output in bps for system.

        '''
        self.logger.debug('Entering get_system_bandwidth_stats method')
        system_bandwidth_stats = self.axapi_call('hd/', 'GET').content.decode()
        self.logger.info(system_bandwidth_stats)
        self.logger.debug('Exiting get_system_bandwidth_stats method')
        return system_bandwidth_stats

    def get_slb_ssl_error(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb ssl error
        '''
        self.logger.debug('Entering get_slb_ssl_error method')
        # BROKEN schema::get_slb_ssl_error_info = self.axapi_call('hd/', 'GET').content.decode()
        get_slb_ssl_error_info =  (self.clideploy(['show slb ssl error']))
        self.logger.info(get_slb_ssl_error_info)
        self.logger.debug('Exiting get_slb_ssl_error method')
        return get_slb_ssl_error_info

    def get_slb_ssl_stats(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb ssl stats
        '''
        self.logger.debug('Entering get_slb_ssl_stats method')
        # BROKEN schema::slb_ssl_stats = self.axapi_call('slb/ssl/stats', 'GET').content.decode()
        slb_ssl_stats = (self.clideploy(['show slb tcp stack']))
        self.logger.info(slb_ssl_stats)
        self.logger.debug('Exiting get_slb_ssl_stats method')
        return slb_ssl_stats

    def get_slb_l4(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb l4
        '''
        self.logger.debug('Entering get_slb_l4 method')
        slb_l4 = self.axapi_call('slb/l4/stats', 'GET').content.decode()
        self.logger.info(slb_l4)
        self.logger.debug('Exiting get_slb_l4 method')
        return slb_l4

    def get_resource_acct_system(self):
        '''
        This section will run the following cmds for the sessions section.

        show resource-accounting resource-type system-resources
        '''
        self.logger.debug('Entering get_resource_acct_system method')
        # BROKEN schema::resource_acct_system = self.axapi_call('hd/', 'GET').content.decode()
        resource_acct_system = (self.clideploy(['show resource-accounting resource-type system-resources']))
        self.logger.info(resource_acct_system)
        self.logger.debug('Exiting get_resource_acct_system method')
        return resource_acct_system

    def get_health_monitor_status(self):
        '''
        This section will run the following cmds for the health monitor status.

        show health stat
        '''
        self.logger.debug('Entering get_health_monitor_status method')
        #health_monitor_status = self.axapi_call('hd/', 'GET').content.decode()
        health_monitor_status = (self.clideploy(['show health stat']))
        self.logger.info(health_monitor_status)
        self.logger.debug('Exiting get_health_monitor_status method')
        return health_monitor_status

    def get_health_monitor_reason(self, N):
        '''
        This section will run the following cmds for the health monitor status. Pass in N for the down-reason

        show health down-reason N
        '''
        self.logger.debug('Entering get_health_monitor_reason method')
        #BROKEN schema: health_monitor_reason = self.axapi_call('health/monitor/stats', 'GET').content.decode()
        health_monitor_reason= (self.clideploy(['show health down-reason ' + N]))
        self.logger.info(health_monitor_reason)
        self.logger.debug('Exiting get_health_monitor_reason method')
        return health_monitor_reason

    def get_performance(self):
        '''
        This section will run the following cmds for the performance section.

        show slb performance
        '''
        self.logger.debug('Entering get_performance method')
        performance = self.axapi_call('slb/perf/stats', 'GET').content.decode()
        self.logger.info(performance)
        self.logger.debug('Exiting get_performance method')
        return performance

    def get_logging_data(self):
        '''Get logs from the device

        show log
        '''
        self.logger.debug('Entering get_logging_data method')
        logging_data = self.axapi_call('syslog/oper', 'GET').content.decode()
        self.logger.info(logging_data)
        self.logger.debug('Exiting get_logging_data method')
        return logging_data

    def get_management_services(self):
        '''gets the currently enabled management services

        show run enable-management
        '''
        self.logger.debug('Entering get_management_services method')
        management_services = json.loads(self.axapi_call('enable-management', 'GET').content.decode())
        self.logger.info(management_services)
        self.logger.debug('Exiting get_management_services method')
        return management_services

    def get_slb_conn_rate_limit_data(self):
        '''gets the results of

        show slb conn-rate-limit src-ip statistics
        '''
        self.logger.debug('Entering get_slb_conn_rate_limit_data method')
        slb_conn_rate_limit_data = self.axapi_call('slb/common/conn-rate-limit', 'GET').content.decode()
        self.logger.info(slb_conn_rate_limit_data)
        self.logger.debug('Exiting get_slb_conn_rate_limit_data method')
        return slb_conn_rate_limit_data

    def get_ip_anomaly_drop(self):
        '''gets the results of any ip anomaly drops

        show ip anomaly-drop
        '''
        self.logger.debug('Entering get_ip_anomaly_drop method')
        ip_anomaly = self.axapi_call('ip/anomaly-drop/stats', 'GET').content.decode()
        self.logger.info(management_services)
        self.logger.debug('Exiting get_ip_anomaly_drop method')
        return ip_anomaly

    def get_version(self):
        '''gets the current version running

        show version
        '''
        self.logger.debug('Entering get_version method')
        version = self.axapi_call('version/oper', 'GET').content.decode()
        self.logger.info(version)
        self.logger.debug('Exiting get_version method')
        return version

    def get_bootimage(self):
        '''get the bootimage configuration

        show bootimage
        '''
        self.logger.debug('Entering get_bootimage method')
        bootimage = self.axapi_call('bootimage/oper', 'GET').content.decode()
        self.logger.info(bootimage)
        self.logger.debug('Exiting get_bootimage method')
        return bootimage

    def pretty_print_json(self, json):
        '''takes a json object and pretty prints it'''
        pretty_json = json.dumps(json, indent=4, sort_keys=True)
        return pretty_json

if __name__ == '__main__':
    main()
