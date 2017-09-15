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
# pylint: disable=C0103

import argparse
import os

import ndr

def main():
    # Get our list of log files
    parser = argparse.ArgumentParser(
        description="Converts a TCPDump PCAP file to a traffic report message and sends it")
    parser.add_argument('-c', '--config',
                        default='/etc/ndr/config.yml',
                        help='NDR Configuration File')
    parser.add_argument('-k', '--keep', help='keep pcap file', action='store_true')
    parser.add_argument('pcaps', nargs='+',
                        help='Packet Capture Files')
    args = parser.parse_args()

    ndr_config = ndr.Config(args.config)
    logger = ndr_config.logger

    for pcap in args.pcaps:
        trm = ndr.TrafficReportMessage(ndr_config)
        logger.info("Processing %s", pcap)
        trm.parse_pcap_file(pcap)

        logger.debug("Processed %d entries", len(trm.traffic_entries))
        logger.debug("Skipped %d local LAN entries", trm.filtered_entries)

        trm.sign_report()
        trm.load_into_queue()

        # Because TCPDump doesn't clean up after itself after processing
        if args.keep is not True:
            os.remove(pcap)

if __name__ == "__main__":
	main()
