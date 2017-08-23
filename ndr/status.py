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

from enum import Enum
import hashlib

import ndr

class StatusMessage(ndr.IngestMessage):
    '''Creates status messages to the server'''
    def __init__(self, config=None):
        self.software_revision = None
        self.files_revision = None

        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.STATUS)

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a Status message record'''
        super().from_message(ingest_msg)
        return self

    @staticmethod
    def hash_file(filename):
        '''Gets the sha256 hash of a file if it exists, else return None'''
        try:
            sha256_hash = hashlib.sha256()
            with open(filename, 'rb') as f:
                while True:
                    data = f.read(65536)
                    if not data:
                        break
                    sha256_hash.update(data)
            return sha256_hash.hexdigest()

        except FileNotFoundError:
            return None

    def populate_status_information(self):
        '''Populates the status information fields from the currently running image'''

        # First, get the easy bit first, which image version
        self.software_revision = self.config.get_image_version()

        # Now let's look at updatable config files, and get the sha256 checksum of them.
        # if the file is MIA, then we don't report it.
        files_dict = {}
        nmap_config_hash = self.hash_file(self.config.nmap_configuration_file)
        if nmap_config_hash is not None:
            files_dict[NdrConfigurationFiles.NMAP_CONFIG.value] = nmap_config_hash

        # Only set files revision if we have local config files
        if len(files_dict) != 0:
            self.files_revision = files_dict
        else:
            self.files_revision = None

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

        if self.files_revision is not None:
            status_dict['config_file_versions'] = self.files_revision

        return status_dict

    def from_dict(self, status_dict):
        '''Deserializes the status message'''

        self.software_revision = status_dict['software_revision']
        self.files_revision = status_dict.get('config_file_versions', None)

class NdrConfigurationFiles(Enum):
    '''Status and configuration files managed by NDR'''
    NMAP_CONFIG = "nmap_config"
