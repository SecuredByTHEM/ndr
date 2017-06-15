#!/usr/bin/python3
# This file is part of NDR.
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

import argparse
import ndr

def run_scans(ndr_config):
    network = "192.168.2.0/24" # FIXME: dehardcode

    # Do host detection passes first to determine what we're scanning
    nmap_runner = ndr.NmapRunner(ndr_config, ndr_config.nmap_scan_interface)
#    host_scan = nmap_runner.arp_host_discovery_scan(network)
#    host_scan.merge(nmap_runner.v6_link_local_scan())

#    ips_to_scan = host_scan.full_ip_list()
#    for ipaddr in ips_to_scan:
#       host_scan.merge(nmap_runner.indepth_host_scan(ipaddr))

    return nmap_runner.scan(ndr.NmapScanTypes.SERVICE_DISCOVERY, "-sS -A -T4", network)

def scan_main(args, ndr_config):
    '''Scans the network'''
    host_scan = run_scans(ndr_config)
    host_scan.sign_report()
    host_scan.load_into_queue()

def main():
    # Parse the command line and then select the correct mode of operation
    parser = argparse.ArgumentParser(
        description="Network Scanner")
    parser.add_argument('--interface', help='interface to scan on')

    subparsers = parser.add_subparsers(help='commands help', dest='command')
    subparsers.required = True

    scan_parser = subparsers.add_parser('scan', help='scan help')
    scan_parser.set_defaults(func=scan_main)

    # Load in the NDR configuration
    ndr_config = ndr.Config('/etc/ndr/config.yml')

    # Handle the operation modes
    args = parser.parse_args()
    args.func(args, ndr_config.logger, ndr_config)

if __name__ == "__main__":
    main()
