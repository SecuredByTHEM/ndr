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

    def populate_status_information(self):
        '''Populates the status information fields from the currently running image'''
        self.software_revision = self.config.get_image_version()

    def create_report(self):
        '''Creates a status report message'''

        # If we're going to send a status message, always make sure it's up to date
        self.populate_status_information()

        self.add_header('payload', self.to_dict())
        super().create_report()

    def to_dict(self):
        '''Prepares a status message for serialization.'''
        status_dict = {}
        status_dict['software_revision'] = self.software_revision

        return status_dict

    def from_dict(self, status_dict):
        '''Deserializes the status message'''

        self.software_revision = status_dict['software_revision']
