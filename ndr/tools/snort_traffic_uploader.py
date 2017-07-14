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
import traceback

import ndr

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
            snort_traffic_log.append_log(logpath)
            continue

        logger.debug("Processing log directory: %s", logpath)
        for _, _, filelist in os.walk(logpath):
            filelist.sort() # Causes the files to be spat out oldest first
            # We're not interested in subdirectories so
            for filename in filelist:
                logfile = logpath+"/"+filename

                try:
                    if filename == args.filename:
                        logger.debug("Skipping base log file: %s", filename)
                        continue
                    logger.debug("Parsing: %s", filename)

                    snort_traffic_log.append_log(logfile)
                    snort_traffic_log.consolate()

                except:
                    trace = traceback.format_exc()
                    logger.error("log parse died with error: %s", trace)
                finally:
                    # Delete the log file after we're done with it
                    os.remove(logfile)

    snort_traffic_log.sign_report()
    snort_traffic_log.load_into_queue()

if __name__ == '__main__':
    main()
