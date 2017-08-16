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
# pylint: disable=W0702

'''Syslog Alerter generates an alert message for specific types of
syslog messages. As of right now, it's invoked by syslog-ng and runs
in a loop reading from stdin'''

import sys
import traceback
import time

import yaml
import ndr

def main():
    '''Sets up processing loop for syslog-ng alerts'''

    ndr_config = ndr.Config('/etc/ndr/config.yml')
    logger = ndr_config.logger

    # Enter processing loop for syslog-ng
    while 1:
        syslog_message = sys.stdin.readline()

        try:
            yaml_line = yaml.safe_load(syslog_message)
            entry = ndr.SyslogEntry.from_dict(yaml_line)

            # Generate an alert message for this entry
            alert_msg = ndr.AlertMessage(ndr_config)
            alert_msg.raised_by = entry.program
            alert_msg.contents = entry.message

            # And send it on its merry way
            alert_msg.sign_report()
            alert_msg.load_into_queue()

        except:
            # Something went wrong, log it, and keep going
            trace = traceback.format_exc()
            logger.error("alertd died with error: %s", trace)
            logger.error("Tried to process %s", syslog_message)

        # Wait ten seconds before trying to read again
        time.sleep(10)

if __name__ == "__main__":
    main()
