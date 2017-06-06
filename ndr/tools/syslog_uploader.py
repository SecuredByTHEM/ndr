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

import logging
import sys
import argparse
import yaml

import ndr
from ndr import SyslogUploadMessage, SyslogEntry

def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    logger = logging.getLogger(name=__name__)
    logger.setLevel(logging.DEBUG)

    # Get our list of log files
    parser = argparse.ArgumentParser(
        description="Upload a JSON-formatted syslog file for processing")
    parser.add_argument('logs', nargs='+',
                        help='log files to upload')
    args = parser.parse_args()

    ndr_config = ndr.Config('/etc/ndr/config.yml')

    # This is slagging ugly. Nothing stops us from getting
    # a bad file in so we need to handle that case, and then
    # pop a message off for each log

    # YAML is a superset of JSON so we should be able to load
    # each line of the log file and pull the object out of with
    # Because of the way syslog-ng logs JSON, we can't simply
    # grab the entire thing because there isn't array markers in
    # the file ..,

    for log in args.logs:
        log_upload = SyslogUploadMessage(ndr_config)
        try:
            with open(log, 'r') as f:
                for line in f:
                    # It's also possible we can get a bad entry. In that case, skip it and report
                    # it into the log. It will get dumped into syslog_upload's syslog error log
                    # for autospy

                    try:
                        yaml_line = yaml.safe_load(line)
                        entry = SyslogEntry.from_dict(yaml_line)
                        if entry == None: # Was a newline, discarding
                            continue
                        log_upload.add_entry(entry)
                    except ValueError:
                        logger.error("failed to parse %s in %s", line, log)
                    except:
                        logger.error("cataphoric error %s %s %s", log, line, sys.exc_info()[0])

            # With everything loaded, queue the magic
            log_upload.sign_report()
            log_upload.load_into_queue()

        finally:
            pass
#    status_msg = SyslogMessage()
if __name__ == "__main__":
	main()
