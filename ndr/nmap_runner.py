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

import ndr
import ndr_netcfg

class NmapConfig(object):
    '''Holds the configuration for NMAP scans'''
    def __init__(self, netcfg_file='/persistant/etc/ndr/network_config.yml'):
        self.scan_interfaces = []
        self.networks_to_scan = []
        self.blacklisted_hosts = []

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

class NmapRunner(object):

    '''Runs NMAP scans on the network'''

    def __init__(self, config, nmap_config):
        self.config = config
        self.nmap_config = nmap_config

    def scan(self, scan_type, options, networks):
        '''Does a IPv4 network scan'''

        xml_logfile = tempfile.mkstemp()

        # Invoke NMAP
        self.config.logger.info("== Running NMap Network Scan ==")

        self.config.logger.debug("Scanning Networks: %s", networks)
        self.config.logger.debug("Options: %s", options)

        # Build the full nmap command line
        nmap_cmd = ["nmap"]
        nmap_cmd += (options.split(" "))

        # Build in XML output
        nmap_cmd += ["-oX", xml_logfile[1]]
        nmap_cmd += [networks]

        self.config.logger.info("NMap Command: %s", ' '.join(nmap_cmd))

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
        nmap_scan = NmapScan(config=self.config)
        nmap_scan.parse_nmap_xml(xml_output)
        nmap_scan.scan_type = scan_type

        return nmap_scan

    def arp_host_discovery_scan(self, network):
        '''Performs a surface scan on the network'''
        return self.scan(NmapScanTypes.ARP_DISCOVERY, "-sn -PR", network)

    def v6_link_local_scan(self, interface):
        '''Performs a link-local scan'''
        return self.scan(NmapScanTypes.IPV6_LINK_LOCAL_DISCOVERY, "-6 -sn -e %s --script=targets-ipv6-multicast-* --script-args=newtargets"
                         % (interface), "")

    def basic_host_scan(self, address):
        '''Does a basic port scan by hosts'''

        # Several bits of magic are required here
        # 1. If we're v6 address or range, we need -6
        # 2. If we're link-local, we need to specify the interface

        return self.scan(NmapScanTypes.PORT_SCAN, "-sS", address)

    def indepth_host_scan(self, address, interface):
        '''Does a full discovery scan'''

        base_nmap_options = "-sS -A -T4"
        ipaddr = ipaddress.ip_address(address)

        options = base_nmap_options
        if ipaddr.version == 6:
            options = "-6 " + options
        if ipaddr.is_link_local:
            options = "-e " + interface + " " + options
        return self.scan(NmapScanTypes.SERVICE_DISCOVERY, options, str(address))
