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
import os

import ndr

def main():
    '''Starts the scan network'''
    parser = argparse.ArgumentParser(
        description="Intelligently scans the network with NMAP")
    parser.add_argument('--net-config',
                        default='/persistant/etc/ndr/network_config.yml',
                        help='Network Configuration File')

    # Load in the NDR configuration
    args = parser.parse_args()

    if os.getuid() != 0:
        print("ERROR: must be run as root")
        return

    # We need the NDR Network config for this scan
    ndr_config = ndr.Config('/etc/ndr/config.yml')
    nmap_config = ndr.NmapConfig(args.net_config)
    nmap_runner = ndr.NmapRunner(ndr_config, nmap_config)

    nmap_runner.run_network_scans()

if __name__ == "__main__":
    main()
