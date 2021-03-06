#!/usr/bin/env python3

'''
Summary:
    This script will generate a report file based on the A10 Health Check. This script was writtien to run every
    command as found in the A10 Health Check document.

    Eventual plans will be to make assessments based on the generated report, however, today the report must be
    reviewed by a qualified A10 expert manually.

Requires:
    - Python 3.x
    - aXAPI v3
    - ACOS 4.1 or higher
    - See additional libraries required on github repo.

Revisions:
            Date        Changes
            2.28.2018   Initial release: bmarlow, tjones


'''
import argparse
import requests
import logging
import inspect
from Acos import Acos
from time import sleep
import datetime


__version__ = '1.0'
__author__ = 'A10 Networks'

parser = argparse.ArgumentParser(description='This program will grab all of the data necessary to do an A10 ACOS SLB health check.')
devices = parser.add_mutually_exclusive_group()
devices.add_argument('-d', '--device', default='192.168.0.152', help='A10 device hostname or IP address. Multiple devices may be included separated by a comma.')
parser.add_argument('-p', '--password', default='a10', help='user password')
parser.add_argument('-u', '--username', default='admin', help='username (default: admin)')
parser.add_argument('-w', '--wait', default=1, type=int, help='How long to delay each API call, longer delays may help to avoid control CPU spikes')
parser.add_argument('-r', '--repeat', default=5, type=int, help='How many times to repeat API calls for SLB perf stats' )
parser.add_argument('-v', '--verbose', default=0, action='count', help='Enable verbose detail')

try:
    args = parser.parse_args()
    devices = args.device.split(',')
    password = args.password
    username = args.username
    wait = args.wait
    verbose = args.verbose
    repeat = args.repeat

except Exception as e:
    print(e)


def main():
    requests.packages.urllib3.disable_warnings()

    # set the default logging format
    logging.basicConfig(format="%(name)s: %(levelname)s: %(message)s")

    start = datetime.datetime.now()
    print('\n\nHealth Check script started at: ' + str(start) + '\n\n')

    for device in devices:
        device = Acos(device, username, password, verbose)
        device.set_logging_env()
        token = device.auth()

        # get a list of partitions (we will iterate over it multiple times later on
        device.partitions = device.get_partition_list()

        # COMMENTS: Print out headers to separate device output
        device.build_section_header("A10 Application Devlivery Controller::AxAPIv3.0")
        device.build_section_header("Data from device at IP::"+device.device)


        healthcheck = HealthCheck()

        # get a list of class methods from healthcheck
        methods_tuples = inspect.getmembers(healthcheck, predicate=inspect.ismethod)
        methods = []

        # iterate through each of the method tuples (name, method) and extract the method
        for method_tuple in methods_tuples:
            methods.append(method_tuple[1])

        # run each of the methods, with the appropriate amount of delay
        # if you want to run specific methods, comment out this for loop and call them below
        for method in methods:
            sleep(wait)
            method(device)

        # example individual call
        # healthcheck.get_running_config(device)


        device.auth_logoff(token)
    end = datetime.datetime.now()
    elapsed = end - start
    print('\n\nHealth Check Script ended at: ' + str(end) + '\n\n')
    print('Time Elapsed: ' + str(elapsed) + '\n\n')


class HealthCheck(object):
    """health check methods"""

    def get_startup_config(self, device):
        """gets the startup config"""
        device.build_section_header("ALL-PARTITIONS STARTUP CONFIGURATION")
        start = device.get_startup_configs()
        print(device.pretty_print_json_as_yaml(start))

    def get_running_config(self, device):
        """gets the running config"""
        device.build_section_header("RUNNING-CONFIG")
        running = device.get_running_configs()
        print(device.pretty_print_json_as_yaml(running))

    def get_json_config(self, device):
        """gets the json config"""
        device.build_section_header("JSON CONFIG")
        json_cfg = device.get_json_config()
        print(device.pretty_print_json_as_yaml(json_cfg))

    def vcs_check(self, device):
        """gets vcs data"""
        device.build_section_header("VCS: /vcs/")
        print(device.pretty_print_json_as_yaml("a10-url: /vcs/images/"))
        print(device.pretty_print_json_as_yaml(device.get_vcs_images()))
        print(device.pretty_print_json_as_yaml("a10-url: /vcs/summary"))
        print(device.pretty_print_json_as_yaml(device.get_vcs_summary()))

    def vrrpa_check(self, device):
        """check vrrp-a data"""
        for partition in device.partitions:
            device.change_partition(partition)
            vrrpa = device.get_vrrpa()
            vrrpa_state = vrrpa['vrrp-a']['state']
            vrrpa_stats = device.get_vrrpa_stats()
            device.build_section_header("Redundancy Check::Partition::" + partition + "::/vrrp-a/state")
            print(device.pretty_print_json_as_yaml("a10-url /vrrp-a/state: "))
            print(device.pretty_print_json_as_yaml(vrrpa_state))
            device.build_section_header("Redundancy Check::Partition::" + partition + "::show vrrp-a detail")
            print(device.pretty_print_json_as_yaml("a10-url /vrrp-a/: "))
            print(device.pretty_print_json_as_yaml(vrrpa))
            device.build_section_header("Redundancy Check::Partition::" + partition + "::show vrrp-a statistics")
            print(device.pretty_print_json_as_yaml("a10-url /vrrp-a/state/stats/: "))
            print(device.pretty_print_json_as_yaml(vrrpa_stats))
        device.change_partition('shared')

    def hardware_health_check(self, device):
        """Perform hardware health check"""
        device.build_section_header("Health Check::Memory::show memory:")
        print(device.pretty_print_json_as_yaml("a10-url /system/memory/oper: "))
        print(device.pretty_print_json_as_yaml(device.get_memory()))
        device.build_section_header("Health Check:HW/DISK:CF::show hardware:")
        print(device.pretty_print_json_as_yaml("a10-url /hardware: "))
        print(device.pretty_print_json_as_yaml(device.get_hardware()))
        device.build_section_header("Health Check:HW/DISK:CF::show disk:")
        print(device.pretty_print_json_as_yaml("a10-url /hardware/oper: "))
        print(device.pretty_print_json_as_yaml(device.get_disk()))
        device.build_section_header("Health Check::HW/DISK:CF::show slb hw-compression:")
        print(device.pretty_print_json_as_yaml("a10-url /slb/hw-compress/stats: "))
        print(device.pretty_print_json_as_yaml(device.get_slb_hw_compression()))
        device.build_section_header("Health Check::HW/DISK:CF:show environment:")
        print(device.pretty_print_json_as_yaml("a10-url /sytem/environment/: "))
        print(device.pretty_print_json_as_yaml(device.get_environment()))
        device.build_section_header("Health Check::HW/DISK:CF::Full System Tree")
        print(device.pretty_print_json_as_yaml("a10-url /sytem/oper: "))
        print(device.pretty_print_json_as_yaml(device.get_system_oper()))

    def interface_trunk_vlan_check(self, device):
        """gets interface data"""
        #Valid cmds for shared partition only
        device.build_section_header("Interface/Trunk/Vlan::show trunk :")
        print(device.pretty_print_json_as_yaml("a10-url /interface/trunk/stats: "))
        print(device.pretty_print_json_as_yaml(device.get_trunk()))
        device.build_section_header("Interface/Trunk/Vlan::show lacp trunk detail:")
        print(device.pretty_print_json_as_yaml("a10-url cli-deploy show lacp trunk detail: "))
        print(device.pretty_print_json_as_yaml(device.get_lacp()))
        device.build_section_header("Interface/Trunk/Vlan::show lacp counters ")
        print(device.pretty_print_json_as_yaml("a10-url /network/lacp/stats: "))
        print(device.pretty_print_json_as_yaml(device.get_lacp_counters()))
        # TODO: need to maybe to check to verify if transceivers are present, else this will give error
        # TODO: will also need to loop through valid fiber interfaces and pass to get_interfaces_transceiver.
        device.build_section_header("Interface/Trunk/Vlan::show interfaces transceiver eth X details:")
        print(device.pretty_print_json_as_yaml("a10-url cli-deploy show interfaces transceiver eth X details: "))
        print(device.pretty_print_json_as_yaml(device.get_interfaces_transceiver()))

        for partition in device.partitions:
            device.change_partition(partition)
            device.build_section_header("Interface/Trunk/Vlan::" + partition + "::show interfaces:")
            print(device.pretty_print_json_as_yaml("a10-url /interface/ethernet/stats: "))
            print(device.pretty_print_json_as_yaml(device.get_interface_ethernet()))
            device.build_section_header("Interface/Trunk/Vlan::" + partition + "::show interfaces ve:")
            print(device.pretty_print_json_as_yaml("a10-url /interface/ve/stats: "))
            print(device.pretty_print_json_as_yaml(device.get_interface_ve()))
            device.build_section_header("Interface/Trunk/Vlan::" + partition + "::show vlans ")
            print(device.pretty_print_json_as_yaml("a10-url /network/vlan/: "))
            print(device.pretty_print_json_as_yaml(device.get_vlans()))
            device.build_section_header("Interface/Trunk/Vlan::" + partition + "::show vlan counters ")
            print(device.pretty_print_json_as_yaml("a10-url /network/vlan/stats: "))
            print(device.pretty_print_json_as_yaml(device.get_vlan_stats()))
        device.change_partition('shared')

    def system_resource_check(self, device):
        """gets systems resources data"""
        for partition in device.partitions:
            device.change_partition(partition)
            resource_accounting = device.get_resource_acct()
            # statically mapping to a list position by index is gross, but Im not smart enough to do it by keyword apparently
            resource_accounting_network = resource_accounting['resource-accounting']['oper']['partition-resource']['partition-name' == partition]['res-type'][0]
            resource_accounting_apps = resource_accounting['resource-accounting']['oper']['partition-resource']['partition-name' == partition]['res-type'][1]
            resource_accounting_system = resource_accounting['resource-accounting']['oper']['partition-resource']['partition-name' == partition]['res-type'][2]
            device.build_section_header("System Resources::Partition::" + partition + "::System Accounting Applications:")
            print(device.pretty_print_json_as_yaml("a10-url /system/resource-accounting/oper"))
            print(device.pretty_print_json_as_yaml(resource_accounting_apps))
            device.build_section_header("System Resources::Partition::" + partition + "::System Accounting Network:")
            print(device.pretty_print_json_as_yaml("a10-url /system/resource-accounting/oper"))
            print(device.pretty_print_json_as_yaml(resource_accounting_network))
            device.build_section_header("System Resources::Partition::" + partition + "::System Accounting:")
            print(device.pretty_print_json_as_yaml("a10-url /system/resource-accounting/oper"))
            print(device.pretty_print_json_as_yaml(resource_accounting_system))
            device.build_section_header("System Resources::Partition::" + partition + "::System ICMP Stats:")
            print(device.pretty_print_json_as_yaml("a10-url /system/icmp/stats: "))
            print(device.pretty_print_json_as_yaml(device.get_icmp_stats()))
            device.build_section_header("System Resources::Partition::" + partition + "::System Bandwidth Stats:")
            print(device.pretty_print_json_as_yaml("a10-url /system/bandwidth/stats: "))
            print(device.pretty_print_json_as_yaml(device.get_system_bandwidth_stats()))
        device.change_partition('shared')

    def system_check(self, device):
        """does a systems check"""
        device.build_section_header("Sessions Check::CPU::Data CPU:")
        print(device.pretty_print_json_as_yaml("a10-url system/data-cpu/stats: "))
        print(device.pretty_print_json_as_yaml(device.get_data_cpu()))
        device.build_section_header("Sessions Check::CPU::Control CPU:")
        print(device.pretty_print_json_as_yaml("a10-url system/control-cpu/stats:"))
        print(device.pretty_print_json_as_yaml(device.get_control_cpu()))
        device.build_section_header("Sessions Check::Spikes::show system cpu-load-sharing:")
        print(device.pretty_print_json_as_yaml("a10-url /system/cpu-load-sharing: "))
        print(device.pretty_print_json_as_yaml(device.get_cpu_load_sharing()))
        device.build_section_header("Sessions Check::Spikes::show cpu history:")
        print(device.pretty_print_json_as_yaml("a10-url /system/data-cpu/: "))
        print(device.pretty_print_json_as_yaml(device.get_cpu_history()))

    def sessions_check(self, device):
        """gets sessions data"""
        device.build_section_header("Sessions Check::show system statistics:")
        print(device.pretty_print_json_as_yaml("a10-url /system/session/stats: "))
        print(device.pretty_print_json_as_yaml(device.get_session()))

        for partition in device.partitions:
            device.change_partition(partition)
            device.build_section_header("Sessions Check::" + partition + "::show ip route:")
            print(device.pretty_print_json_as_yaml("a10-url ip/fib/oper: "))
            print(device.pretty_print_json_as_yaml(device.get_ip_route()))
            device.build_section_header("Sessions Check::" + partition + "::show ip stats:")
            print(device.pretty_print_json_as_yaml("a10-url /ip/stats: "))
            print(device.pretty_print_json_as_yaml(device.get_ip_stats()))
            device.build_section_header("Sessions Check::" + partition + "show slb switch (TCP STATS):")
            print(device.pretty_print_json_as_yaml("a10-url /slb/switch/stats"))
            switch_stats = device.get_slb_switch()
            switch_stats = switch_stats['switch']['stats']
            for key, value in switch_stats.items():
                if 'tcp' in key:
                    print(device.pretty_print_json_as_yaml(key + ':' + str(value)))

            device.build_section_header("Sessions Check::" + partition + "show slb switch (UDP STATS):")
            print(device.pretty_print_json_as_yaml("a10-url /slb/switch/stats: "))
            for key, value in switch_stats.items():
                if 'udp' in key:
                    print(device.pretty_print_json_as_yaml(key + ':' + str(value)))

            device.build_section_header("Sessions Check::" + partition + "show slb tcp stack:")
            print("a10-url system/tcp: ")
            print(device.pretty_print_json_as_yaml(device.get_slb_tcp_stack()))

            device.build_section_header("Sessions Check::" + partition + "show slb ssl error:")
            print("a10-url cli-deploy show slb ssl error: ")
            print(device.pretty_print_json_as_yaml(device.get_slb_ssl_error()))

            device.build_section_header("Sessions Check::" + partition + "show slb ssl stats:")
            print("a10-url cli-deploy show slb ssl stats: ")
            print(device.pretty_print_json_as_yaml(device.get_slb_ssl_stats()))

            device.build_section_header("Sessions Check::" + partition + "show slb l4 detail:")
            print("a10-url /slb/l4/stats: ")
            print(device.pretty_print_json_as_yaml(device.get_slb_l4()))
        device.change_partition('shared')
        # this may fail on some devices prior to 4.1.1-P6/7, shared partition only
        device.build_section_header("Sessions Check::show ip anomaly-drop statistics :")
        print(device.pretty_print_json_as_yaml("a10-url /ip/anomaly-drop/stats"))
        print(device.pretty_print_json_as_yaml(device.get_ip_anomaly_drop()))

    def system_errors_check(self, device):
        """gets systems errors data"""
        device.build_section_header(" System Errors::show log | i Errors: ")
        print("a10-url syslog/oper: ")
        logs = device.pretty_print_json_as_yaml(device.get_logging_data()).split('\n')
        keyword_list = ['Error', 'Warning', 'Critical']
        for line in logs:
            if any(word in line for word in keyword_list):
                print(line)

    def health_monitor_check(self, device):
        """gets health monitor data"""
        for partition in device.partitions:
            device.change_partition(partition)
            device.build_section_header(" Health Monitor Status::" + partition + "::show health monitor: ")
            print("a10-url /health/monitor: ")
            print(device.pretty_print_json_as_yaml(device.get_health_monitor()))
            device.build_section_header("Health Monitor Status::" + partition + "show health stat:")
            print("a10-url cli-deploy show health stat: ")
            health_stat = (device.get_health_monitor_status())
            print(device.pretty_print_json_as_yaml(health_stat))
            device.build_section_header("Health Monitor Status::" + partition + "::show health down-reason N:")
            print("a10-url cli-deploy show health down-reason N: ")
            # the health_stat.values() is passed to the other method, but not used.  That seems incorrect.
            dr_list = device.get_hm_down_reasons()
            if '0' in dr_list:
                dr_list.remove('0')
            else:
                for dr in list(set(dr_list)):
                    print(device.pretty_print_json_as_yaml(device.get_health_monitor_reason(dr)))
        device.change_partition('shared')

    def performance_data_check(self, device):
        """gets performance data"""
        device.build_section_header("Performance Data: /system/performance:")
        i = 0  # Iterator
        print("a10-url /system/performance: ")
        for i in range(0, args.repeat):
            print(device.pretty_print_json_as_yaml(device.get_performance()))
            sleep(1.0)
            args.repeat -= 1

    def application_services_check(self, device):
        device.build_section_header('Application Services')
        device.build_section_header("Application Services::show slb server:")
        print("a10-url /slb/server/oper: ")
        print(device.pretty_print_json_as_yaml(device.get_slb_server_oper()))
        device.build_section_header("Application Services::show slb service-group:")
        print("a10-url /slb/service-group/oper: ")
        print(device.pretty_print_json_as_yaml(device.get_slb_service_group_oper()))
        device.build_section_header("Application Services::show slb virtual-server:")
        print("a10-url /slb/virtual-server/oper: ")
        print(device.pretty_print_json_as_yaml(device.get_slb_virtual_server_oper()))
        # iterate through each partition
        for partition in device.partitions:
            # change to the first partition
            device.change_partition(partition)
            device.build_section_header('PARTITION: ' + partition)
            # instantiate empty list of servers
            servers = []
            # get json list of servers
            slb_servers = device.get_slb_servers()

            try:
                # for each server in the list (if isn't empty) add the name as a value
                if slb_servers:
                    for server in slb_servers['server-list']:
                        servers.append(server['name'])

                    # for each named server print a header then the stat information
                    for server in servers:
                        server_stats = device.get_slb_server_stats(server)
                        device.build_section_header('Stats for partition: ' + partition + '::SLB SERVER ' + server)
                        print(device.pretty_print_json_as_yaml(server_stats))

            except KeyError:
                print('There are no SLB Servers configured on partition ' + partition)

            # instantiate an empty list of service-groups
            service_groups = []
            # get the json list of service-groups
            slb_service_groups = device.get_slb_service_groups()

            try:
                # for each service-group in the list (if it isn't empty) add the name as a value
                if slb_service_groups:
                    for service_group in slb_service_groups['service-group-list']:
                        service_groups.append(service_group['name'])

                    # for each named service-group print a header then the stat information
                    for service_group in service_groups:
                        service_group_stats = device.get_slb_service_group_stats(service_group)
                        device.build_section_header(
                            'Stats for partition: ' + partition + '::SLB SERVICE-GROUP ' + service_group)
                        print(device.pretty_print_json_as_yaml(service_group_stats))

            except KeyError:
                print('There are no SLB Service-Groups on partition ' + partition)

            # instantiate an empty list of virtual-servers
            virtual_servers = []
            # get teh json list of virtual-servers
            slb_virtual_servers = device.get_slb_virtual_servers()

            try:
                # for each virtual-server in the list (if it isn't empty) add the name as a value
                if slb_virtual_servers:
                    for virtual_server in slb_virtual_servers['virtual-server-list']:
                        virtual_servers.append(virtual_server['name'])

                    # for each named virtual-server print a header then the stat information
                    for virtual_server in virtual_servers:
                        virtual_server_stats = device.get_slb_virtual_server_stats(virtual_server)
                        device.build_section_header(
                            'Stats for partition: ' + partition + '::SLB VIRTUAL-SERVER ' + virtual_server)
                        print(device.pretty_print_json_as_yaml(virtual_server_stats))

            except KeyError:
                print('There are no SLB Virtual Servers configured on partition ' + partition)

        device.change_partition('shared')

    def monitoring_check(self, device):
        device.build_section_header('Monitoring Review::show run logging')
        print("a10-url /logging: ")
        print(device.pretty_print_json_as_yaml(device.get_logging()))

    def security_check(self, device):
        """gets the information for the security check"""
        device.build_section_header('Security Check::show management')
        print("a10-url enable-management: ")
        print(device.pretty_print_json_as_yaml(device.get_management_services()))
        device.build_section_header('Security Check::show slb conn-rate-limit src-ip statistics')
        print("a10-url /slb/common/conn-rate-limit: ")
        print(device.pretty_print_json_as_yaml(device.get_slb_conn_rate_limit_data()))
        device.build_section_header('Security Check::show ip anomaly-drop statistics')
        print("a10-url ip/anomaly-drop/stats: ")
        print(device.pretty_print_json_as_yaml(device.get_ip_anomaly_drop()))

    def version_check(self, device):
        """gets the information for the version check"""
        device.build_section_header('Version Check::show version')
        print('a10-url /system/version')
        print(device.pretty_print_json_as_yaml(device.get_version()))
        device.build_section_header('Version Check::show bootimage')
        print('a10-url cli-deploy show bootimage')
        print(device.pretty_print_json_as_yaml(device.get_bootimage()))


if __name__ == '__main__':
    main()
