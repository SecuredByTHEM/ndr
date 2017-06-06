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

import logging
import argparse
import ndr

def run_scans(logger, ndr_config):
    network = "192.168.2.0/24" # FIXME: dehardcode

    # Do host detection passes first to determine what we're scanning
    nmap_runner = ndr.NmapRunner(ndr_config, ndr_config.nmap_scan_interface)
#    host_scan = nmap_runner.arp_host_discovery_scan(network)
#    host_scan.merge(nmap_runner.v6_link_local_scan())

#    ips_to_scan = host_scan.full_ip_list()
#    for ipaddr in ips_to_scan:
 #       host_scan.merge(nmap_runner.indepth_host_scan(ipaddr))

    return nmap_runner.scan(ndr.NmapScanTypes.SERVICE_DISCOVERY, "-sS -A -T4", network)

def create_baseline(logger, ndr_config):
    '''Creates the baseline file'''
    with open(ndr_config.baseline_scan, 'w') as bls:
        host_scan = run_scans(logger, ndr_config)
        bls.write(host_scan.to_yaml())

    logger.info("baseline scan saved to %s", ndr_config.baseline_scan)

def baseline_main(args, logger, ndr_config):
    '''Controls functions related to changes in the baseline'''
    if args.create:
        create_baseline(logger, ndr_config)

def scan_main(args, logger, ndr_config):
    '''Scans the network'''
    host_scan = run_scans(logger, ndr_config)
    host_scan.sign_report()
    host_scan.load_into_queue()

def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    logger = logging.getLogger(name=__name__)
    logger.setLevel(logging.DEBUG)

    # Parse the command line and then select the correct mode of operation
    parser = argparse.ArgumentParser(
        description="Network Scanner")
    parser.add_argument('--interface', help='interface to scan on')

    subparsers = parser.add_subparsers(help='commands help', dest='command')
    subparsers.required = True
    baseline_parser = subparsers.add_parser('baseline', help='baseline help')

    # Baseline manipulation options
    baseline_parser.add_argument('--create',
                                 action="store_true",
                                 help="Creates network baseline")
    baseline_parser.set_defaults(func=baseline_main)

    scan_parser = subparsers.add_parser('scan', help='scan help')
    scan_parser.set_defaults(func=scan_main)

    # Load in the NDR configuration
    ndr_config = ndr.Config('/etc/ndr/config.yml')

    # Handle the operation modes
    args = parser.parse_args()
    args.func(args, logger, ndr_config)

if __name__ == "__main__":
    main()
