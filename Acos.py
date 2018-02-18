import requests
from requests.exceptions import HTTPError
import datetime
import json
import logging


# Class for making all device calls using AxAPI v3.0
class Acos(object):
    def __init__(self, device, username, password, verbose):
        self.device = device
        self.username = username
        self.password = password
        self.verbose = verbose
        self.base_url = 'https://' + device + '/axapi/v3/'
        self.headers = {'content-type': 'application/json'}
        self.logger = logging.getLogger(self.device)


    def set_logging_env(self):
        """Set logging environment for the device"""

        dt = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

        logging.basicConfig(format="%(name)s: %(levelname)s: %(message)s")

        # set your verbosity levels
        if self.verbose == 0:
            self.logger.setLevel(logging.ERROR)

        elif self.verbose == 1:
            self.logger.setLevel(logging.INFO)

        elif self.verbose >= 2:
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
        try:
            auth_token = authorization['authresponse']['signature']

        except TypeError:
            self.logger.error('The following error occurred while authenticating')
            self.logger.error('\n' + authorization)
            exit(1)

        self.headers['Authorization'] = 'A10 ' + auth_token
        self.logger.debug('Exiting the auth method')
        return auth_token

    def auth_logoff(self, token):
        """authenticates and retrives the auth token for the A10 device"""

        self.logger.debug('Logging Off to clean up session.')
        self.headers['Authorization'] = 'A10 ' + token

        try:
            log_off = self.axapi_call('logoff', 'POST')

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

        try:
            r = json.loads(r.content.decode())

        except json.JSONDecodeError:
            if r.status_code == '204':
                r = 'HTTP 204'
            else:
                r = r.content.decode()



        self.logger.info(r)
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
        return self.start_config_all_parts

    def get_running_configs(self):
        """Returns the running configuration for an A10 device. Uses cli-deploy method."""
        self.run_config_with_def_all_parts = self.clideploy(['show running with-default partition-config all'])
        self.logger.debug('Exiting get_running_config method')
        return self.run_config_with_def_all_parts

    def get_json_config(self):
        """Returns the json configuration for an A10 device. Uses cli-deploy method."""
        self.run_json_config = (self.clideploy(['show json-config']))
        self.logger.debug('Exiting get_json_config method')
        return self.run_json_config

    def build_section_header(self, section):
        """prints section headers"""
        print('{:*^100s}'.format(''))
        print('{:*^100s}'.format(section))
        print('{:*^100s}'.format(''))

    def get_partition_list(self):
        """gets a list of all the partition names"""
        # instatiate list with shared partition as it is implied and not returned by the REST endpoint
        partitions = ['shared']
        partition_list = self.axapi_call('partition', 'GET')
        try:
            for partition in partition_list['partition-list']:
                partitions.append(partition["partition-name"])
        except TypeError:
            # if there are no partitions (or only shared), then catch and move on
            pass
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
        self.logger.debug('Entering get_vrrpa method')
        vrrpa = self.axapi_call('vrrp-a', 'GET')
        #vrrpa_common = self.axapi_call('vrrp-a/common/', 'GET')

        self.logger.debug('Exiting get_vrrpa method')
        return vrrpa

    def get_vrrpa_stats(self):
        """gets vrrp-a stats"""
        self.logger.debug('Entering get_vrrpa_stats method')
        vrrpa_stats = self.axapi_call('vrrp-a/state/stats', 'GET')
        self.logger.debug('Exiting get_vrrpa method')
        return vrrpa_stats

    def get_vcs_images(self):
        """gets a list of vcs images"""

        self.logger.debug('Entering get_vcs_images method')
        vcs_images = (self.axapi_call('vcs/images/oper', 'GET'))
        self.logger.debug('Exiting get_vcs_images method')
        return vcs_images

    def get_vcs_summary(self):
        """gets the vcs summary"""

        self.logger.debug('Entering get_vcs_summary method')
        vcs_summary = (self.axapi_call('vcs/vcs-summary/oper', 'GET'))
        self.logger.debug('Exiting get_vcs_summary method')
        return vcs_summary

    def get_slb_servers(self):
        """gets a list of all slb servers"""

        self.logger.debug('Entering get_slb_servers method')
        servers_list = self.axapi_call('slb/server', 'GET')

        self.logger.info(servers_list)
        self.logger.debug('Exiting get_slb_servers method')
        return servers_list

    def get_slb_service_groups(self):
        """gets a list of all service-groups"""

        self.logger.debug('Entering get_slb_service_groups method')
        service_group_list = self.axapi_call('slb/service-group', 'GET')


        self.logger.info(service_group_list)
        self.logger.debug('Exiting get_slb_service_groups method')
        return service_group_list

    def get_slb_virtual_servers(self):
        """gets a list of all virtual-servers"""

        self.logger.debug('Entering get_slb_virtual_servers method')
        virtual_server_list = self.axapi_call('slb/virtual-server', 'GET')

        self.logger.info(virtual_server_list)
        self.logger.debug('Exiting get_slb_virtual_servers method')
        return virtual_server_list

    def get_slb_server_stats(self, server):
        """gets operational stats for a slb server"""

        self.logger.debug('Entering get_slb_server_stats method')
        slb_server_stats = self.axapi_call('slb/server/' + server + '/stats', 'GET')
        self.logger.info(slb_server_stats)
        self.logger.debug('Exiting get_slb_server_stats method')
        return slb_server_stats

    def get_slb_service_group_stats(self, service_group):
        """get operational stats for a service-group"""

        self.logger.debug('Entering get_slb_service_group_stats method')
        service_group_stats = self.axapi_call('slb/service-group/' + service_group + '/stats', 'GET')
        self.logger.info(service_group_stats)
        self.logger.debug('Exiting get_slb_service_group_stats method')
        return service_group_stats

    def get_slb_virtual_server_stats(self, virtual_server):
        """get operation stats for a virtual-server"""
        self.logger.debug('Entering get_slb_service_group_stats method')
        virtual_server_stats = self.axapi_call('slb/virtual-server/' + virtual_server + '/stats', 'GET')
        self.logger.info(virtual_server_stats)
        self.logger.debug('Exiting get_slb_service_group_stats method')
        return virtual_server_stats

    def get_slb_server_oper(self, server):
        """gets operational status for a server"""
        self.logger.debug('Entering get_slb_server_oper method')
        server_oper = self.axapi_call('slb/server/' + server + '/oper', 'GET')
        self.logger.info(server_oper)
        self.logger.debug('Exiting get_slb_server_oper method')
        return server_oper

    def get_slb_service_group_oper(self, service_group):
        """gets operational status for a service-group"""
        self.logger.debug('Entering get_slb_service_group_oper method')
        service_group_oper = self.axapi_call('slb/service-group/' + service_group + '/oper', 'GET')
        self.logger.info(service_group_oper)
        self.logger.debug('Exiting get_slb_service_group_oper method')
        return service_group_oper

    def get_slb_virtual_server_oper(self, virtual_server):
        """gets operational status for a virtual_server"""
        self.logger.debug('Entering get_slb_virtual_server_oper method')
        virtual_server_oper = self.axapi_call('slb/virtual-server/' + virtual_server + '/oper', 'GET')
        self.logger.info(virtual_server_oper)
        self.logger.debug('Exiting get_slb_virtual_server_oper method')
        return virtual_server_oper

    def get_memory(self):
        '''
        show memory
        '''
        self.logger.debug('Entering get_memory method')
        memory_info = self.axapi_call('system/memory/oper', 'GET')
        self.logger.info(memory_info)
        self.logger.debug('Exiting get_memory method')
        return memory_info

    def get_system_oper(self):
        '''
        show oper
        '''
        self.logger.debug('Entering get_system_oper method')
        system_oper = self.axapi_call('system/oper/', 'GET')
        self.logger.info(system_oper)
        self.logger.debug('Exiting get_system_oper method')
        return system_oper

    def get_health(self):
        '''
        show health monitor
        '''
        self.logger.debug('Entering get_health method')
        health_info = self.axapi_call('health/monitor', 'GET')
        self.logger.info(health_info)
        self.logger.debug('Exiting get_health method')
        return health_info

    # rework me /slb/health-check-summary
    # this doesn't even look used, maybe remove?
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
        hardware = self.axapi_call('system/hardware/', 'GET')
        self.logger.info(hardware)
        self.logger.debug('Exiting get_hardware method')
        return hardware

    def get_disk(self):
        '''
        show disk
        '''
        self.logger.debug('Entering get_disk method')
        disk = self.axapi_call('system/hardware/oper', 'GET')
        self.logger.info(disk)
        self.logger.debug('Exiting get_disk method')
        return disk

    def get_slb_hw_compression(self):
        '''
        show slb hw-compression
        '''
        self.logger.debug('Entering get_slb_hw_compression method')
        slb_hw_compression = self.axapi_call('slb/hw-compress/stats', 'GET')
        self.logger.info(slb_hw_compression)
        self.logger.debug('Exiting get_slb_hw_compression method')
        return slb_hw_compression

    def get_environment(self):
        '''
        Hardware only

        show environment
        '''
        self.logger.debug('Entering get_environment method')
        evironment = self.axapi_call('system/environment', 'GET')
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
        # TODO: Update to only run on fiber ports.
        interfaces_transceiver = self.clideploy(['show interfaces transceiver ethernet 9 details'])
        self.logger.info(interfaces_transceiver)
        self.logger.debug('Exiting get_fiber_info method')
        return interfaces_transceiver

    def get_interface_ethernet(self):
        '''
        This section will run the following cmds for ethernet interfaces

        show interfaces
        '''
        self.logger.debug('Entering get_interface_ethernet method')
        interface_ethernet = self.axapi_call('interface/ethernet/stats', 'GET')
        self.logger.info(interface_ethernet)
        self.logger.debug('Exiting get_interface_ethernet method')
        return interface_ethernet

    def get_interface_ve(self):
        '''
        This section will run the following cmds for ethernet interfaces

        show interfaces ve
        '''
        self.logger.debug('Entering get_interface_ve method')
        interface_ve = self.axapi_call('interface/ve/stats', 'GET')
        self.logger.info(interface_ve)
        self.logger.debug('Exiting get_interface_ve method')
        return interface_ve

    def get_trunk(self):
        '''
        This section will run the following cmds for trunk interfaces

        show trunk
        '''
        self.logger.debug('Entering get_trunk method')
        trunk = self.axapi_call('interface/trunk/stats', 'GET')
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
        lacp_counters = self.axapi_call('network/lacp/stats', 'GET')
        self.logger.info(lacp_counters)
        self.logger.debug('Exiting get_lacp_counters method')
        return lacp_counters

    def get_vlans(self):
        '''
        This section will run the following cmds for vlans
        show vlans
        '''
        self.logger.debug('Entering get_vlans method')
        vlans = self.axapi_call('network/vlan', 'GET')
        self.logger.info(vlans)
        self.logger.debug('Exiting get_vlans method')
        return vlans

    def get_vlan_stats(self):
        '''
        This section will run the following cmds for vlans
        show vlan counters
        '''
        self.logger.debug('Entering get_vlan_stats method')
        vlan_stats = self.axapi_call('network/vlan/stats', 'GET')
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
        system_resources_usage = self.axapi_call('system/resource-usage/oper', 'GET')
        self.logger.info(system_resources_usage)
        self.logger.debug('Exiting get_system_resources_usage_info method')
        return system_resources_usage

    def get_slb_resource_usage(self):
        '''
        This section will run all of the system resource section commands.
        NOTE: some of these are not available on all ACOS versions.

        show slb resource-usage
        '''
        self.logger.debug('Entering get_slb_resource_usage method')
        slb_resource_info = self.axapi_call('slb/resource-usage/oper', 'GET')
        self.logger.info(slb_resource_info)
        self.logger.debug('Exiting get_slb_resource_usage method')
        return slb_resource_info

    def get_resource_acct(self):
        """gets the platform/application accounting details"""
        self.logger.debug('Entering get_resource_acct method')
        resource_acct = self.axapi_call('system/resource-accounting/oper', 'GET')
        self.logger.info(resource_acct)
        self.logger.debug('Exiting get_resource_acct method')
        return resource_acct

    def get_icmp_stats(self):
        '''
        This section will run the following cmds for the CPU

        show system icmp
        '''
        self.logger.debug('Entering get_icmp_stats method')
        get_icmp_stats = self.axapi_call('system/icmp/stats', 'GET')
        self.logger.info(get_icmp_stats)
        self.logger.debug('Exiting get_icmp_stats method')
        return get_icmp_stats

    def get_data_cpu(self):
        """returns the utilization values for the data cpus"""
        self.logger.debug('Entering get_data_cpu method')
        data_cpu_info = (self.axapi_call('system/data-cpu/stats', 'GET'))
        self.logger.info(data_cpu_info)
        self.logger.debug('Exiting get_data_cpu method')
        return data_cpu_info

    def get_control_cpu(self):
        """returns the utilization values for the control cpus"""
        self.logger.debug('Entering get_control_cpu method')
        control_cpu_info = (self.axapi_call('system/control-cpu/stats', 'GET'))
        self.logger.info(control_cpu_info)
        self.logger.debug('Exiting get_control_cpu method')
        return control_cpu_info

    def get_cpu_load_sharing(self):
        '''
        This section will run the following cmds for the CPU

        show cpu
        '''
        self.logger.debug('Entering get_cpu_load_sharing method')
        cpu_load_sharing = self.axapi_call('system/cpu-load-sharing', 'GET')
        self.logger.info(cpu_load_sharing)
        self.logger.debug('Exiting get_cpu_load_sharing method')
        return cpu_load_sharing

    def get_cpu_overall(self):
        '''
        This section will run the following cmd for the CPU

        show cpu overall
        '''
        self.logger.debug('Entering get_cpu_overall method')
        # BROKEN schema::cpu_overall_info = self.axapi_call('system/data-cpu/overall', 'GET')
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
        # BROKEN schema::cpu_history = self.axapi_call('system/data-cpu/', 'GET')
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
        session = self.axapi_call('system/session/stats', 'GET')
        self.logger.info(session)
        self.logger.debug('Exiting get_session method')
        return session

    def get_ip_route(self):
        """gets a list of routes from the device"""
        self.logger.debug('Entering the get_ip_route method')
        routes = self.axapi_call('ip/fib/oper', 'GET')
        self.logger.info(routes)
        self.logger.debug('Exiting the get_ip_route method')

        return routes

    def get_ip_stats(self):
        '''
        This section will run the following cmds for the sessions section.

        show ip stats
        '''
        self.logger.debug('Entering get_ip_stats method')
        ip_stats = self.axapi_call('ip/stats', 'GET')
        self.logger.info(ip_stats)
        self.logger.debug('Exiting get_ip_stats method')
        return ip_stats

    def get_slb_switch(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb switch
        '''
        self.logger.debug('Entering get_slb_switch method')
        slb_switch = self.axapi_call('slb/switch/stats', 'GET')
        self.logger.info(slb_switch)
        self.logger.debug('Exiting get_slb_switch method')
        return slb_switch

    def get_slb_tcp_stack(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb tcp stack
        '''
        self.logger.debug('Entering get_slb_tcp_stack method')
        # BROKEN schema::get_session_info = self.axapi_call('hd/', 'GET')
        slb_tcp_stack = (self.clideploy(['show slb tcp stack']))
        self.logger.info(slb_tcp_stack)
        self.logger.debug('Exiting get_slb_tcp_stack method')
        return slb_tcp_stack

    def get_system_bandwidth_stats(self):
        '''
        This function will return total input/output in bps for system.

        '''
        self.logger.debug('Entering get_system_bandwidth_stats method')
        system_bandwidth_stats = self.axapi_call('/system/bandwidth/stats', 'GET')
        self.logger.info(system_bandwidth_stats)
        self.logger.debug('Exiting get_system_bandwidth_stats method')
        return system_bandwidth_stats

    def get_slb_ssl_error(self):
        '''
        This section will run the following cmds for the sessions section.

        show slb ssl error
        '''
        self.logger.debug('Entering get_slb_ssl_error method')
        # BROKEN schema::get_slb_ssl_error_info = self.axapi_call('hd/', 'GET')
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
        # BROKEN schema::slb_ssl_stats = self.axapi_call('slb/ssl/stats', 'GET')
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
        slb_l4 = self.axapi_call('slb/l4/stats', 'GET')
        self.logger.info(slb_l4)
        self.logger.debug('Exiting get_slb_l4 method')
        return slb_l4

    def get_resource_acct_system(self):
        '''
        This section will run the following cmds for the sessions section.

        show resource-accounting resource-type system-resources
        '''
        self.logger.debug('Entering get_resource_acct_system method')
        # BROKEN schema::resource_acct_system = self.axapi_call('hd/', 'GET')
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
        # health_monitor_status = self.axapi_call('hd/', 'GET')
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
        # BROKEN schema: health_monitor_reason = self.axapi_call('health/monitor/stats', 'GET')
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
        performance = self.axapi_call('slb/perf/stats', 'GET')
        self.logger.info(performance)
        self.logger.debug('Exiting get_performance method')
        return performance

    def get_logging_data(self):
        '''Get logs from the device

        show log
        '''
        self.logger.debug('Entering get_logging_data method')
        logging_data = self.axapi_call('syslog/oper', 'GET')
        self.logger.info(logging_data)
        self.logger.debug('Exiting get_logging_data method')
        return logging_data

    def get_logging(self):
        '''Get logs from the device

        show log
        '''
        self.logger.debug('Entering get_logging method')
        logging = self.axapi_call('/logging', 'GET')
        self.logger.info(logging)
        self.logger.debug('Exiting get_logging method')
        return logging

    def get_management_services(self):
        '''gets the currently enabled management services

        show run enable-management
        '''
        self.logger.debug('Entering get_management_services method')
        management_services = self.axapi_call('enable-management', 'GET')
        self.logger.debug('Exiting get_management_services method')
        return management_services

    def get_slb_conn_rate_limit_data(self):
        '''gets the results of

        show slb conn-rate-limit src-ip statistics
        '''
        self.logger.debug('Entering get_slb_conn_rate_limit_data method')
        slb_conn_rate_limit_data = self.axapi_call('slb/common/conn-rate-limit', 'GET')
        self.logger.info(slb_conn_rate_limit_data)
        self.logger.debug('Exiting get_slb_conn_rate_limit_data method')
        return slb_conn_rate_limit_data

    def get_ip_anomaly_drop(self):
        '''gets the results of any ip anomaly drops

        show ip anomaly-drop
        '''
        self.logger.debug('Entering get_ip_anomaly_drop method')
        ip_anomaly = self.axapi_call('ip/anomaly-drop/stats', 'GET')
        self.logger.info(ip_anomaly)
        self.logger.debug('Exiting get_ip_anomaly_drop method')
        return ip_anomaly

    def get_version(self):
        '''gets the current version running

        show version
        '''
        self.logger.debug('Entering get_version method')
        version = self.axapi_call('version/oper', 'GET')
        self.logger.info(version)
        self.logger.debug('Exiting get_version method')
        return version

    def get_bootimage(self):
        '''get the bootimage configuration

        show bootimage
        '''
        self.logger.debug('Entering get_bootimage method')
        bootimage = self.axapi_call('bootimage/oper', 'GET')
        self.logger.info(bootimage)
        self.logger.debug('Exiting get_bootimage method')
        return bootimage

    def pretty_print_json(self, json_obj):
        '''takes a json object and pretty prints it'''
        pretty_json = json.dumps(json_obj, indent=4, sort_keys=True)
        return pretty_json