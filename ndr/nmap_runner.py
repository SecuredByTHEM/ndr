# This file is part of NDR.
#
# Copyright (C) 2017 - Secured By THEM
# Original Author: Michael Casadevall <michaelc@them.com>
#
# NDR is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# NDR is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NDR.  If not, see <http://www.gnu.org/licenses/>.

'''Holds the configuration information for NMAP'''

import tempfile
import subprocess
import os
import ipaddress

from enum import Enum

import ndr
import ndr_netcfg
import yaml

class NmapConfig(object):
    '''Holds the configuration for NMAP scans'''
    def __init__(self,
                 netcfg_file='/persistant/etc/ndr/network_config.yml',
                 nmap_cfgfile='/persistant/etc/ndr/nmap_config.yml'):
        self.scan_interfaces = []
        self.networks_to_scan = []
        self.nmap_cfgfile = nmap_cfgfile

        # Handle our blacklists here.
        self.basic_only_ips = []
        self.basic_only_macs = []
        self.blacklist_ips = []
        self.blacklist_macs = []

        # Pull our interfaces from the NDR network configuration
        netcfg = ndr_netcfg.NetworkConfiguration(netcfg_file)
        interfaces = netcfg.get_all_managed_interfaces()

        # Loop through the interfaces we'll scan on
        for interface in interfaces:
            if 'lan' not in interface.name:
                continue # Interface we don't care about

            # Add this interface to networks we care about
            self.scan_interfaces.append(interface.name)

            # Append the networks we're configured for to the list
            for addr in interface.current_ip_addresses:
                self.networks_to_scan.append(
                    addr.ip_network()
                )

        # This config file is optional so it's non-fatal if we don't find it
        try:
            with open(nmap_cfgfile, 'r') as f:
                config_dict = f.read()
                cfg_dict = yaml.safe_load(config_dict)
                if cfg_dict is not None: # What happens when pyYAML reads an empty file
                    self.from_dict(cfg_dict)

        except FileNotFoundError:
            self.nmap_cfgfile = None

    def to_dict(self):
        '''Persistant storage of blacklists - may expand in the future'''
        config_dict = {}

        # Basic Only means we port scan but don't run with -A
        config_dict['version'] = 1

        # Machines are listed by key/value pairs under the machine_mac dict
        # or the machine_ip dict for the behavior wanted

        # Supported keywords as of right now as blacklist or basic_only
        machine_mac = {}
        machine_ip = {}

        for mac_address in self.basic_only_macs:
            machine_mac[mac_address] = NmapMachineMode.BASIC_ONLY.value

        for mac_address in self.blacklist_macs:
            machine_mac[mac_address] = NmapMachineMode.BLACKLIST.value

        for ip_addr in self.basic_only_ips:
            machine_ip[ip_addr.compressed] = NmapMachineMode.BASIC_ONLY.value

        for ip_addr in self.blacklist_ips:
            machine_ip[ip_addr.compressed] = NmapMachineMode.BLACKLIST.value

        config_dict['machine_ips'] = machine_ip
        config_dict['machine_macs'] = machine_mac

        return config_dict

    def from_dict(self, config_dict):
        '''Load settings from dictionary'''
        # Load the easy objects first
        if config_dict.get('version', None) != 1:
            raise ValueError("Unknown NDR NMAP config file version!")

        # Clean out the IP lists
        self.basic_only_ips = []
        self.blacklist_ips = []
        self.basic_only_macs = []
        self.blacklist_macs = []

        machine_ips = config_dict.get('machine_ips', dict())
        machine_macs = config_dict.get('machine_macs', dict())

        # Load in the machine IP addresses
        for ip_addr, value in machine_ips.items():
            enum_value = NmapMachineMode(value)
            if enum_value == NmapMachineMode.BASIC_ONLY:
                self.basic_only_ips.append(ipaddress.ip_address(ip_addr))
            elif enum_value == NmapMachineMode.BLACKLIST:
                self.blacklist_ips.append(ipaddress.ip_address(ip_addr))

        # Now do it again with the MAC addresses
        for mac_addr, value in machine_macs.items():
            enum_value = NmapMachineMode(value)
            if enum_value == NmapMachineMode.BASIC_ONLY:
                self.basic_only_macs.append(mac_addr)
            elif enum_value == NmapMachineMode.BLACKLIST:
                self.blacklist_macs.append(mac_addr)

    def write_configuration(self):
        '''Writes out the persistant configuration file'''
        with open(self.nmap_cfgfile, 'w') as f:
            f.write(yaml.safe_dump(self.to_dict()))

class NmapRunner(object):

    '''Runs NMAP scans on the network'''

    def __init__(self, config, nmap_config):
        self.config = config
        self.nmap_config = nmap_config

    def run_scan(self, scan_type, options, target):
        '''Does a IPv4 network scan'''

        xml_logfile = tempfile.mkstemp()

        # Invoke NMAP
        self.config.logger.debug("Scanning Target: %s", target)
        self.config.logger.debug("Options: %s", options)

        # Build the full nmap command line
        nmap_cmd = ["nmap"]
        nmap_cmd += (options.split(" "))

        # Build in XML output
        nmap_cmd += ["-oX", xml_logfile[1]]

        if target is not None:
            nmap_cmd += [target.compressed]

        self.config.logger.debug("NMap Command: %s", ' '.join(nmap_cmd))

        nmap_proc = subprocess.run(
            args=nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

        if nmap_proc.returncode != 0:
            raise ndr.NmapFailure(nmap_proc.returncode,
                                  str(nmap_proc.stderr, 'utf-8'))

        xml_output = None
        with open(xml_logfile[1], 'r') as nmap_file:
            xml_output = nmap_file.read()
        os.remove(xml_logfile[1])

        # Build a scan object and return it
        nmap_scan = ndr.NmapScan(config=self.config)
        nmap_scan.parse_nmap_xml(xml_output)
        nmap_scan.scan_type = scan_type

        # Scan targets MUST be in CIDR form, so convert the target to a ipnetwork
        if target is not None:
            target_net = ipaddress.ip_network(target.compressed)
            nmap_scan.scan_target = target_net.compressed
        return nmap_scan

    def arp_host_discovery_scan(self, network):
        '''Performs a ARP surface scan on the network'''
        return self.run_scan(NmapScanTypes.ARP_DISCOVERY, "-sn -R -PR", network)

    def nd_host_discovery_scan(self, network):
        '''Performs a ND surface scan on the network'''
        return self.run_scan(NmapScanTypes.ND_DISCOVERY, "-6 -R -sn -PR", network)


    def v6_link_local_scan(self, interface):
        '''Performs a link-local scan'''
        return self.run_scan(NmapScanTypes.IPV6_LINK_LOCAL_DISCOVERY,
                             "-6 -R -sn -e %s --script=targets-ipv6-multicast-* --script-args=newtargets"
                             % (interface), None)

    def build_nmap_commandline(self, base_flags, address, interface=None):
        '''Builds common NMAP option command lines'''
        ipaddr = ipaddress.ip_address(address)


        # Several bits of magic are required here
        # 1. If we're v6 address or range, we need -6
        # 2. If we're link-local, we need to specify the interface

        options = base_flags
        if ipaddr.version == 6:
            options = "-6 " + options
        if ipaddr.is_link_local:
            options = "-e " + interface + " " + options

        return options

    def basic_host_scan(self, address, interface=None):
        '''Does a basic port scan by hosts'''

        options = self.build_nmap_commandline("-sS", address, interface)
        return self.run_scan(NmapScanTypes.PORT_SCAN, options, address)

    def protocol_scan(self, address, interface=None):
        '''Scans the network to determine what, if any IP protocols are supported'''

        options = self.build_nmap_commandline("-sO", address, interface)
        return self.run_scan(NmapScanTypes.IP_PROTOCOL_DETECTION, options, address)

    def indepth_host_scan(self, address, interface=None):
        '''Does a full discovery scan'''

        options = self.build_nmap_commandline("-sS -A -T4", address, interface)
        return self.run_scan(NmapScanTypes.SERVICE_DISCOVERY, options, address)

    def run_network_scans(self):
        '''Runs a scan of a network and builds an iterative map of the network'''

        def process_and_send_scan(scan, interface=None, append=False):
            '''Appends a list of IP addresses to scan further down the line'''
            hosts_in_scan = []
            for found_ip in scan.full_ip_and_mac_list():
                logger.debug("Discovered host %s", found_ip)
                if append is True:
                    hosts_in_scan.append((found_ip, interface))
                    
            if append is True:
                logger.debug("Discovered %d hosts in total this scan", len(hosts_in_scan))

            scan.sign_report()
            scan.load_into_queue()

            return hosts_in_scan


        # During NMAP scanning, we will run this in multiple stages to determine what, if anything
        # if on the network, and then do additional scans beyond that point based on the data we
        # detect and determine. By default, we only scan the L2 segment we're on.

        logger = self.config.logger

        scan_interfaces = self.nmap_config.scan_interfaces
        networks_to_scan = self.nmap_config.networks_to_scan

        # First we need to generate a list of everything we can detect link local
        logger.info("== Running NMap Network Scan ==")

        if self.nmap_config.nmap_cfgfile is not None:
            logger.info("Using config file %s", self.nmap_config.nmap_cfgfile)
        else:
            logger.info("No configuration file, using defaults")

        logger.info("Phase 1: Link-Local Discovery")

        discovered_hosts = []

        for interface in scan_interfaces:
            logger.info("Scaning on %s", interface)

            logger.info("Performing IPv6 link-local discovery scan")
            ipv6_ll_scan = self.v6_link_local_scan(interface)

            discovered_hosts += process_and_send_scan(ipv6_ll_scan, interface=interface, append=True)


        logger.info("Phase 2: Network Discover")

        # Now we need to do host discovery on each network we have we have to scan
        for network in networks_to_scan:
            if network.version == 4:
                logger.info("Performing ARP host discovery on %s", network)
                arp_discovery = self.arp_host_discovery_scan(network)
                discovered_hosts += process_and_send_scan(arp_discovery, append=True)
            else:
                # IPv6
                logger.info("Performing ND host discovery on %s", network)
                nd_discovery = self.nd_host_discovery_scan(network)
                discovered_hosts += process_and_send_scan(nd_discovery, append=True)


        # Now we need to figure out what protocols each host supports
        logger.info("Phase 3: Machine Scanning")

        # HACK: quick and dirty deduplicate sorting. We can get multiple duplicates due to
        # ndr-netcfg sometimes returning the same IP twice. How troublesome. Need to sort that
        # out

        discovered_hosts = list(set(discovered_hosts))

        for host_tuple in discovered_hosts:
            # Now we need to build a list of what to scan vs. what not to. Right now
            # we've got the IP address and the MAC addr of each host, so now if they are
            # blacklisted, then we bail out
            host_ip = host_tuple[0][0]
            mac_address = host_tuple[0][1]
            interface = host_tuple[1]


            # FIXME: We should use protocol discovery here and refine our scans based on it, but
            # at the moment, that requires a fair bit of additional code to be written, so we'll
            # address it later

            # Determine if we need to skip stuff due to a blacklist
            if ipaddress.ip_address(host_ip) in self.nmap_config.blacklist_ips:
                logger.info("Skipping IP %s due to blacklist", host_ip)
                continue

            if mac_address in self.nmap_config.blacklist_macs:
                logger.info("Skipping IP %s due to MAC %s blacklist", host_ip, mac_address)
                continue

            basic_scan = False

            if ipaddress.ip_address(host_ip) in self.nmap_config.basic_only_ips:
                logger.info("Degrading %s to basic scan due to NMAP config", host_ip)
                basic_scan = True

            if mac_address in self.nmap_config.basic_only_macs:
                logger.info("Degrading %s to basic scan due to NMAP config", host_ip)
                basic_scan = True

            # For now, we'll simply do a protocol scan so we can get an idea of what exists
            # out there in the wild
            
            # MC - disabling protocol scan for now due to performance
            #logger.debug("Running protocol scan on %s", host_ip)
            #protocol_scan = self.protocol_scan(host_ip, interface)
            #process_and_send_scan(protocol_scan)

            # Now begin in-depth scanning of things. If a host is blacklisted,
            # then it's noted and skipped at this point

            logger.info("Phase 4: Host Scanning")

            if basic_scan is True:
                logger.info("Basic scanning %s", host_ip)
                host_scan = self.basic_host_scan(host_ip, interface)
            else:
                logger.info("In-depth scanning %s", host_ip)
                host_scan = self.indepth_host_scan(host_ip, interface)
            process_and_send_scan(host_scan)

class NmapScanTypes(Enum):

    '''Types of scans we do with NMAP'''
    ARP_DISCOVERY = "arp-discovery"
    IPV6_LINK_LOCAL_DISCOVERY = 'ipv6-link-local-discovery'
    IP_PROTOCOL_DETECTION = "ip-protocol-detection"
    PORT_SCAN = "port-scan"
    SERVICE_DISCOVERY = "service-discovery"
    ND_DISCOVERY = "nd-discovery"

class NmapMachineMode(Enum):
    '''Machine configurations recognized by NMAP Runner'''
    BASIC_ONLY = "basic-only"
    BLACKLIST = "blacklist"