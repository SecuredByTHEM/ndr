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

import csv
import argparse
import os
import sys

import ndr

def parse_log(logger, traffic_log, logfile):
    '''Parses an individual log file'''

    try:
        with open(logfile, 'r') as f:
            reader = csv.DictReader(f, ['timestamp',
                                        'proto',
                                        'src',
                                        'srcport',
                                        'dst',
                                        'dstport',
                                        'ethsrc',
                                        'ethdst',
                                        'ethlen',
                                        'tcpflags',
                                        'tcpseq'])
            for row in reader:
                try:
                    traffic_entry = ndr.SnortTrafficEntry()
                    traffic_entry.from_csv(row)
                    traffic_log.traffic_entries.append(traffic_entry)
                except ValueError:
                    logger.error("failed to parse %s in %s: %s", row, logfile, sys.exc_info()[1])
                except:
                    logger.error("cataphoric error %s %s %s", logfile, row, sys.exc_info()[0])
    finally:
        pass

def main():
    parser = argparse.ArgumentParser(
        description="Uploads SNORT all-traffic CSV files. If directory is specified, all files in that directory")
    parser.add_argument('-f', "--filename", default='log.csv', help='base name of the log file to upload')
    parser.add_argument('logs', nargs='+',
                        help='log files to upload')
    args = parser.parse_args()

    ndr_config = ndr.Config('/etc/ndr/config.yml')

    snort_traffic_log = ndr.SnortTrafficLog(ndr_config)
    logger = ndr_config.logger

    for logpath in args.logs:
        if os.path.isfile(logpath):
            logger.debug("Processing log: %s", logpath)
            parse_log(logger, ndr_config, logpath)
            continue

        logger.debug("Processing log directory: %s", logpath)
        for _, _, filelist in os.walk(logpath):
            filelist.sort() # Causes the files to be spat out oldest first
            # We're not interested in subdirectories so
            for filename in filelist:
                if filename == args.filename:
                    logger.debug("Skipping base log file: %s", filename)
                    continue
                logger.debug("Parsing: %s", filename)
                parse_log(logger, snort_traffic_log, logpath+filename)

        # Testing output
        #import pprint
        #pprint.pprint(snort_traffic_log.to_dict())

    logger.info("Starting consolation")
    snort_traffic_log.consolate()
    logger.info("Done")

    snort_traffic_log.create_report()

if __name__ == '__main__':
    main()
