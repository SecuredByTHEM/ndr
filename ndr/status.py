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

'''Creates status messages reporting OTA and such information'''

import ndr

class StatusMessage(ndr.IngestMessage):
    '''Creates status messages to the server'''
    def __init__(self, config=None):
        self.software_revision = None
        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.STATUS)

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a Status message record'''
        super().from_message(ingest_msg)
        return self

    def create_report(self):
        '''Creates a status report message'''
        super().create_report()

    def to_dict(self):
        '''Prepares a SnortTrafficLog for serialization.

        Only consolated data is serialized. Run consolate() before this function'''
        return None

    def from_dict(self, traffic_dict):
        '''Deserializes a SnortTrafficLog'''
        pass
