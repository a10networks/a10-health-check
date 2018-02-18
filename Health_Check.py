#!/usr/bin/env python3

'''
Summary:
    This script will generate a report file based on the A10 Health Check. This script is only meant to run every
    command as found in the health check.

    Eventual plans will be to make assessments based on the generated report, however, today the report must be
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
import urllib3
import logging
from Acos import Acos
from time import sleep


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


def main():
    urllib3.disable_warnings()

    # set the default logging format
    logging.basicConfig(format="%(name)s: %(levelname)s: %(message)s")

    for device in devices:
        device = Acos(device, username, password, verbose)
        device.set_logging_env()
        token = device.auth()

        # get a list of partitions (we will iterate over it multiple times later on
        device.partitions = device.get_partition_list()

        ##################################################################################
        # Turn On/Off Data to be collected (for normal full health check, set all to true
        ##################################################################################
        # COMMENTS: May be another way, just making easier to either run full report or pieces
        full_check = False
        if full_check == True:  # Run all sections
            get_startup_cfg = full_check            # Get startup config for all partitions
            get_running_cfg = full_check            # Get running config for all partitions
            get_json_cfg = full_check               # Get config for all partitions in JSON format
            get_vcs = full_check                    # Get vcs information
            get_vrrpa = full_check                  # Get VRRP-a information
            get_vrrpa_partitions = full_check       # Get VRRP-a information for all partitions
            get_health_check = full_check           # Get data from health-check section
            get_interface_info = full_check         # Get interface/trunk/vlan stats
            get_system_resource_info = full_check   # Get the current system resources info
            get_cpu_info = full_check               # Get the CPU information
            get_sessions_info = full_check          # Get the current sessions info
            get_system_error_info = False           # Get error cmd output (NOTE: not in v4.x code as of v4.1.1, v4.1.4)
            get_health_monitor_stat = full_check  # Get the health monitor stats for all servers in all partitions
            get_perf_data = full_check              # Get the performance information for the system
            get_application_stats = full_check      # Get all slb (servers,service-group, vips) stats
            get_monitoring_check = full_check       # Get all output for the Monitoring Check section
            get_security_check = full_check         # Get all output for the Security section
            get_version_check = full_check          # Get the version information
        else: # Else set individual sections to run.
            get_startup_cfg = False                 # Get startup config for all partitions
            get_running_cfg = False                 # Get running config for all partitions
            get_json_cfg = False                    # Get config for all partitions in JSON format
            get_vcs = False                         # Get vcs information
            get_vrrpa = False                       # Get VRRP-a information
            get_vrrpa_partitions = False            # Get VRRP-a information for all partitions
            get_health_check = False                # Get data from health-check section
            get_interface_info = False              # Get interface/trunk/vlan stats
            get_system_resource_info = False        # Get the current system resources info
            get_cpu_info = False                    # Get the CPU information
            get_sessions_info = False               # Get the current sessions info
            get_system_error_info = False           # Get error cmd output (NOTE: not in v4.x code as of v4.1.1, v4.1.4)
            get_health_monitor_stat = False         # Get the health monitor stats for all servers in all partitions
            get_perf_data = False                   # Get the performance information for the system
            get_application_stats = False           # Get all slb (servers,service-group, vips) stats
            get_monitoring_check = False            # Get all output for the Monitoring Check section
            get_security_check = False              # Get all output for the Security section
            get_version_check = False               # Get the version information
        ##################################################################################
        # Print Device Section Header
        ##################################################################################
        # COMMENTS: Print out headers to separate device output
        device.build_section_header("A10 Application Devlivery Controller::AxAPIv3.0")
        device.build_section_header("Data from device at IP::"+device.device)


        ##################################################################################
        # Capture & Save Configurations
        ##################################################################################
        # COMMENTS: Run to collect the startup-config for all partitions
        if get_startup_cfg == False:
            print("Skipping startup-config")
        else:
            device.build_section_header("ALL-PARTITIONS STARTUP CONFIGURATION")
            run = device.get_startup_configs()
            print(run)

        # COMMENTS: Run to collect the running-config for all partitions
        if get_running_cfg == False:
            print("Skipping running-config")
        else:
            device.build_section_header("RUNNING-CONFIG")
            start = device.get_running_configs()
            print(start)

        # COMMENTS: Run to collect json-config for all partitions
        if get_json_cfg == False:
            print("Skipping JSON config")
        else:
            device.build_section_header("JSON CONFIG")
            json_cfg = device.get_json_config()
            print(json_cfg)


        ##################################################################################
        # Check VCS
        ##################################################################################
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
        if get_vcs == False:
            print("Skipping VCS.")
        else:
            device.build_section_header("VCS: /vcs/")
            print("a10-url: /vcs/images/")
            print(device.get_vcs_images())
            print("a10-url: /vcs/summary")
            print(device.get_vcs_summary())



        ##################################################################################
        # VRRP-A Check
        ##################################################################################
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
        if get_vrrpa == False:
            print("Skipping VRRP-A.")
        else:
            device.build_section_header("VRRP-A: /shared/vrrp-a/:")
            vrrpa = device.get_vrrpa()
            vrrpa_stats = device.get_vrrpa_stats()

            print("a10-url /vrrp-a/: ")
            print(vrrpa)

            print("a10-url /vrrp-a/state/stats/: ")
            print(vrrpa_stats)

        # REDUNDANCY CHECK: VRRP-A PARTITIONS
        # COMMENTS: Run all cmds for all-partitions
        # TODO: Add some code to check for vrrp-a before running cmds. Skip if no vrrp-a.
        if get_vrrpa_partitions == False:
            print("Skipping VRRP-a all-partitions.")
        else:
            partitions = device.get_partition_list()
            for part in partitions:
                device.change_partition(part)
                print(device.get_json_config())
                vrrpa, detail, common, stats = device.get_vrrpa()
                device.build_section_header("Redundancy Check::Partition::"+part+"/vrrp-a")
                print("a10-url /vrrp-a/: ")
                print(vrrpa)
                device.build_section_header("Redundancy Check::Partition::"+part+"::show vrrp-a detail")
                print("a10-url /vrrp-a/detail/: ")
                print(detail)
                device.build_section_header("Redundancy Check::Partition::"+part+"::show vrrp-a common")
                print("a10-url /vrrp-a/common/: ")
                print(common)
                device.build_section_header("Redundancy Check::Partition::"+part+"::show vrrp-a statistics")
                print("a10-url /vrrp-a/state/stats/: ")
                print(stats)



        ##################################################################################
        # Health Check
        ##################################################################################
        # COMMENTS: Only required for shared partition
        if get_health_check == False:
            print("Skipping Health Check.")
        else:
            device.build_section_header("Health Check::Memory::show memory:")
            print("a10-url /system/memory/oper: ")
            print(device.get_memory())
            device.build_section_header("Health Check:HW/DISK:CF::show hardware:")
            print("a10-url /hardware: ")
            print(device.get_hardware())
            device.build_section_header("Health Check:HW/DISK:CF::show disk:")
            print("a10-url /hardware: ")
            print(device.get_disk())
            device.build_section_header("Health Check::HW/DISK:CF::show slb hw-compression:")
            print("a10-url /slb/hw-compress/stats: ")
            print(device.get_slb_hw_compression())
            device.build_section_header("Health Check::HW/DISK:CF:show environment:")
            print("a10-url /sytem/environment/: ")
            print(device.get_environment())
            device.build_section_header("Health Check::HW/DISK:CF::Full System Tree")
            print("a10-url /sytem/oper: ")
            print(device.get_system_oper())



        ##################################################################################
        # Interface/Trunk/Vlan Check
        ##################################################################################
        # COMMENTS:
        if get_interface_info == False:
            print("Skipping Interface/Trunk/Vlan.")
        else:
            device.build_section_header("Interface/Trunk/Vlan::show interfaces:")
            print("a10-url /interface/ethernet/stats: ")
            print(device.get_interface_ethernet())
            device.build_section_header("Interface/Trunk/Vlan::show interfaces ve:")
            print("a10-url /interface/ve/stats: ")
            print(device.get_interface_ve())
            # TODO: need to maybe to check to verify if transceivers are present, else this will give error
            device.build_section_header("Interface/Trunk/Vlan::show interfaces transceiver eth X details:")
            print("a10-url cli-deploy show interfaces transceiver eth X details: ")
            print(device.get_interfaces_transceiver())
            device.build_section_header("Interface/Trunk/Vlan::show trunk :")
            print("a10-url /interface/trunk/stats: ")
            print(device.get_trunk())
            device.build_section_header("Interface/Trunk/Vlan::show lacp trunk detail:")
            print("a10-url cli-deploy show lacp trunk detail: ")
            print(device.get_lacp())
            device.build_section_header("Interface/Trunk/Vlan::show lacp counters ")
            print("a10-url /network/lacp/stats: ")
            print(device.get_lacp_counters())
            device.build_section_header("Interface/Trunk/Vlan::show vlans ")
            print("a10-url /network/vlan/: ")
            print(device.get_vlans())
            device.build_section_header("Interface/Trunk/Vlan::show vlan counters ")
            print("a10-url /network/vlan/stats: ")
            print(device.get_vlan_stats())



        ##################################################################################
        # System Resources
        ##################################################################################
        # COMMENTS:
        if get_system_resource_info == False:
            print("Skipping System Resources.")
        else:
            '''device.build_section_header("System Resources: show system resource-usage:")
            print("a10-url /system/resouce-usage/oper: ")
            print(device.get_system_resources_usage())
            device.build_section_header("System Resources::show slb resource-usage:")
            print("a10-url /slb/resources-usage/oper: ")
            print(device.get_slb_resource_usage())
            device.build_section_header("System Resources::show resource-accounting all-partitions summary:")
            print("a10-url cli-deploy show resource-accounting all-partitions summary: ")
            '''
            for partition in device.partitions:
                device.change_partition(partition)
                resource_accounting = device.get_resource_acct()

                # statically mapping to a list position by index is gross, but Im not smart enough to do it by keyword apparently
                resource_accounting_network = resource_accounting['resource-accounting']['oper']['partition-resource']['partition-name' == partition]['res-type'][0]
                resource_accounting_apps = resource_accounting['resource-accounting']['oper']['partition-resource']['partition-name' == partition]['res-type'][1]
                resource_accounting_system = resource_accounting['resource-accounting']['oper']['partition-resource']['partition-name' == partition]['res-type'][2]

                device.build_section_header("System Resources::Partition::" + partition + "::System Accounting Applications:")
                print("a10-url /system/resource-accounting/oper")
                print(resource_accounting_apps)
                device.build_section_header("System Resources::Partition::" + partition + "::System Accounting Network:")
                print("a10-url /system/resource-accounting/oper")
                print(resource_accounting_network)
                device.build_section_header("System Resources::Partition::" + partition + "::System Accounting:")
                print("a10-url /system/resource-accounting/oper")
                print(resource_accounting_system)
                device.build_section_header("System Resources::Partition::" + partition + "System ICMP Stats:")
                print("a10-url /system/icmp/stats: ")
                print(device.get_icmp_stats())
                device.build_section_header("System Resources::Partition::" + partition + "System Bandwidth Stats:")
                print("a10-url /system/bandwidth/stats: ")
                print(device.get_system_bandwidth_stats())


        ##################################################################################
        # System Check::CPU
        ##################################################################################
        # COMMENTS:
        # TODO: Need to look to pull more CPU for control plane in. No history api call found
        if get_cpu_info == False:
            print("Skipping Sessions Check::CPU.")
        else:
            device.build_section_header("Sessions Check::CPU::Data CPU:")
            print("a10-url system/data-cpu/stats: ")
            print(device.get_data_cpu())

            device.build_section_header("Sessions Check::CPU::Control CPU:")
            print("a10-url system/control-cpu/stats:")
            print(device.get_control_cpu())

            device.build_section_header("Sessions Check::Spikes::show system cpu-load-sharing:")
            print("a10-url /system/cpu-load-sharing: ")
            print(device.get_cpu_load_sharing())

            device.build_section_header("Sessions Check::Spikes::show cpu history:")
            print("a10-url /system/data-cpu/: ")
            print(device.get_cpu_history())



        ##################################################################################
        # Sessions Check
        ##################################################################################
        # COMMENTS:
        if get_sessions_info == False:
            print("Skipping Sessions Check.")
        else:

            for partition in device.partitions:
                device.change_partition(partition)

                device.build_section_header("Sessions Check::Partition::" + partition + "::show system:")
                print("a10-url /system/session/stats: ")
                print(device.get_session())

                device.build_section_header("Sessions Check::Partition::" + partition + "::Routes:")
                print("a10-url ip/fib/oper: ")
                print(device.get_ip_route())

                device.build_section_header("Sessions Check::Partition::" + partition + "show ip stats:")
                print("a10-url /ip/stats: ")
                print(device.get_ip_stats())

                # this may fail on some devices prior to 4.1.1-P6/7
                device.build_section_header("Sessions Check::show ip anomaly-drop statistics :")
                print("a10-url /ip/anomaly-drop/stats")
                print(device.get_ip_anomaly_drop())

                device.build_section_header("Sessions Check::show slb switch (TCP STATS):")
                print("a10-url /slb/switch/stats")
                switch_stats = device.get_slb_switch()
                switch_stats = switch_stats['switch']['stats']
                for key, value in switch_stats.items():
                    if 'tcp' in key:
                        print(key + ':' + str(value))

                device.build_section_header("Sessions Check::show slb switch (UDP STATS):")
                print("a10-url /slb/switch/stats: ")
                for key, value in switch_stats.items():
                    if 'udp' in key:
                        print(key + ':' + str(value))

                device.build_section_header("Sessions Check::show slb tcp stack:")
                print("a10-url system/tcp: ")
                print(device.get_slb_tcp_stack())

                device.build_section_header("Sessions Check::show slb ssl error:")
                print("a10-url cli-deploy show slb ssl error: ")
                print(device.get_slb_ssl_error())

                device.build_section_header("Sessions Check::show slb ssl stats:")
                print("a10-url cli-deploy show slb ssl stats: ")
                print(device.get_slb_ssl_stats())

                device.build_section_header("Sessions Check::show slb l4 detail:")
                print("a10-url /slb/l4/stats: ")
                print(device.get_slb_l4())

        ##################################################################################
        # System Errors
        ##################################################################################
        # COMMENTS:
        if get_system_error_info == False:
            print("Skipping System Errors.")
        else:
            device.build_section_header("System Errors: /system/ :")
            device.build_section_header("Sessions Check::show resource-accounting resource-type system-resources:")
            print("a10-url /system/errors: ")
            # TODO: Only print out the logs with ERROR/CRITICAL/WARNING
            print(device.get_logging_data())


        ##################################################################################
        # Health Monitor Status
        ##################################################################################
        # COMMENTS:
        if get_health_monitor_stat == False:
            print("Skipping Health Monitor Status.")
        else:
            device.build_section_header("Health Monitor Status::show health stat:")
            # TODO: Add the partition loop to check all paritions
            print("a10-url cli-deploy show health stat: ")
            print(device.get_health_monitor_status())
            device.build_section_header("Health Monitor Status::show health down-reason N:")
            # TODO: will need to check for downed resources, get a list of down servers, get reason, then run cmd
            print("a10-url cli-deploy show health down-reason N: ")
            print(device.get_health_monitor_reason('15')) #Static for now


        ##################################################################################
        # Performance Data
        ##################################################################################
        # COMMENTS:
        if get_perf_data == False:
            print("Skipping Performance Data.")
        else:
            device.build_section_header("Performance Data: /system/performance:")
            # TODO: this cmd will require a loop and execute for t seconds, where t = 60 (but configurable).
            N = 5      # Number of seconds to collect the performance data
            i = 0       # Iterator
            print("a10-url /system/performance: ")
            for i in range(0,N):
                print(device.get_performance())
                sleep(1.0)
                N = N-1


        ##################################################################################
        # Application Services
        ##################################################################################
        # COMMENTS:
        if get_application_stats == False:
            print("Skipping Application Services.")
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
        # COMMENTS:
        if get_monitoring_check == False:
            print("Skipping Monitoring Check.")
        else:
            device.build_section_header('Monitoring Review::show run logging')
            print("a10-url /logging: ")
            print(device.get_logging())


        ##################################################################################
        # Security Check
        ##################################################################################
        #COMMNETS:
        if get_security_check == False:
            print("Skipping Security Check.")
        else:
            device.build_section_header('Security Check::show management')
            print("a10-url enable-management: ")
            print(device.get_management_services())
            device.build_section_header('Security Check::show slb conn-rate-limit src-ip statistics')
            print("a10-url /slb/common/conn-rate-limit: ")
            print(device.get_slb_conn_rate_limit_data())
            device.build_section_header('Security Check::show ip anomaly-drop statistics')
            print("a10-url ip/anomaly-drop/stats: ")
            print(device.get_ip_anomaly_drop())


        ##################################################################################
        # Version Check
        ##################################################################################
        #COMMENTS:
        if get_version_check == False:
            print("Skipping Version Check.")
        else:
            device.build_section_header('Version Check::show version')
            print('a10-url /system/version')
            print(device.get_version())
            device.build_section_header('Version Check::show bootimage')
            print('a10-url cli-deploy show bootimage')
            print(device.get_bootimage())
        ##################################################################################
        # Logoff AxAPI session
        ##################################################################################
        # COMMENTS: Always run logoff to ensure proper clean-up. If sessions are not closed, the login users
        # will be exceeded and the script can fail due to the maximum number of logins exceeded
        device.auth_logoff(token)



if __name__ == '__main__':
    main()
