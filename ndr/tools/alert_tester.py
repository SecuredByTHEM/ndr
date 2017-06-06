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

'''Causes an alert notification to happen on demand to make sure that a client is setup
   correctly during setup'''

import ndr

def main():
    ndr_config = ndr.Config('/etc/ndr/config.yml')
    ingest_message = ndr.IngestMessage(
        ndr_config, ndr.IngestMessageTypes.TEST_ALERT
    )

    ingest_message.sign_report()
    ingest_message.load_into_queue()

if __name__ == "__main__":
	main()
