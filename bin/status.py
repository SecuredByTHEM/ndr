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
from ndr.ingest_message import IngestMessage, IngestMessageTypes

class StatusReport:
    def __init__(self):
        pass

    def status_report(self):
        msg = IngestMessage(IngestMessageTypes.STATUS, "status-logger")
        msg.add_header("uptime", 1234)
        message = msg.create_report()

        msg.sign_report()
        msg.load_into_queue()

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    logger = logging.getLogger(name=__name__)
    logger.setLevel(logging.DEBUG)

    #sn = ScanNetwork(logger)
    #sn.v4_scan()

    status_msg = StatusReport()
    status_msg.status_report()
