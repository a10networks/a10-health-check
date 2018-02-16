#!/usr/bin/env python3

'''
Summary:
    This script will parse objects grabbed by the Health_Check.py tool and provide feedback based on the output

Requires:
    - Python 3.x
    - aXAPI v3
    - ACOS 4.0 or higher

Revisions:
    - 0.1 - initial script generation by A10 engineers: Brandon Marlow, Terry Jones

'''

import urllib3
import argparse
import logging
import json
from Health_Check import Acos

parser = argparse.ArgumentParser(description='Running this script will issue whatever commands are presented to this script.  All commands are issued from configuration mode.')
devices = parser.add_mutually_exclusive_group()
devices.add_argument('-d', '--device', default='10.0.1.221', help='A10 device hostname or IP address. Multiple devices may be included seperated by a comma.')
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
        device.set_logging_env()

        ##################################################################################
        # Capture Current Configs
        ##################################################################################




        ##################################################################################
        # Redundancy Check
        ##################################################################################

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

        conn_rate_limit = device.get_slb_conn_rate_limit_data()

        admin_services = device.get_management_services()

        #print(json.dumps(admin_services, indent=4))

        device.build_section_header('Management Services Reivew')

        # services to check
        services = ['ping', 'ssh', 'telnet', 'http', 'https', 'snmp']
        data_service_enabled = False
        for service in services:
            try:

                interfaces = admin_services['enable-management']['service'][service]['eth-cfg']

                interface_list = []

                for interface in interfaces:

                    if interface['ethernet-start'] == interface['ethernet-end']:
                        interface_list.append(interface['ethernet-start'])
                        data_service_enabled = True

                    else:
                        interface_range = range(interface['ethernet-start'], interface['ethernet-end'] + 1)
                        for item in interface_range:
                            interface_list.append(item)
                            data_service_enabled = True

                print(service.upper() + ' service is enabled on the following interfaces: ' + str(interface_list))

            except KeyError:
                print(service.upper() + ' is not enabled on any data-plane interfaces.')


        mgmt_services = []
        for service in services:

            try:
                mgmt_service = admin_services['enable-management']['service'][service]['management']

                if mgmt_service == 1:
                    mgmt_services.append(service.upper())


            except KeyError:
                pass

        print('The following services are enabled on the management interface: ' + str(mgmt_services))

        if data_service_enabled:
            print('')
            print('Please note that by default no management services are enabled on data interfaces.')
            print('The current configuration has management services enabled on data interfaces.')
            print('Please review that the management services running on the data plane are necessary.')


        ##################################################################################
        # Version/Bootimage Check
        ##################################################################################



        ##################################################################################
        # Logoff
        ##################################################################################
        device.auth_logoff(token)
        device.logger.info('Successfully Logged off of device')

if __name__ == '__main__':
    main()
