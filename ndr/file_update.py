# This file is part of NDR.
#
# Copyright (C) 2017 - Secured By THEM
# Original Author: Michael Casadevall <mcasadevall@them.com>
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

import os
import tempfile
import shutil

import base64

import ndr

'''Handles file update operations for NDR'''

def get_file_location(config, file_enum: ndr.NdrConfigurationFiles):
    '''Gets a file location if NDR client config is provided,
       else none'''
    if config is None:
        return None

    return {
        ndr.NdrConfigurationFiles.NMAP_CONFIG: config.nmap_configuration_file
    }[file_enum]


class FileObject(object):
    '''Representation of a file'''

    def __init__(self, config=None):
        self.config = config
        self.file_type = None
        self.binary_data = None
        self.file_location = None

    def encode_file(self, file_type: ndr.NdrConfigurationFiles, binary_data: bytes):
        '''Encodes a file for the file object'''

        self.file_type = file_type
        self.binary_data = binary_data
        self.file_location = get_file_location(self.config, file_type)

    def write_file(self):
        '''Writes out the file on the filesystem'''
        if self.file_location is None:
            raise ValueError("Will not encode a file without a config being passed in!")

        # Normally, best practice is to write the file to a scratch file, then
        # move it in place, but atomically fails if $TMP and the destination are on
        # two different files. We'll try to do that here, and use shutils.move which
        # will do it atomically if possible, else copy and replace if it can't

        scratch_file = None
        success = False

        try:
            fd, scratch_file = tempfile.mkstemp()
            os.close(fd)

            with open(scratch_file, 'wb') as f:
                f.write(self.binary_data)

            shutil.move(scratch_file, self.file_location)
            success = True

        finally:
            # Delete the temp file if we failed before we re-reaise
            if scratch_file is not None and success is False:
                os.remove(scratch_file)

    def to_dict(self):
        '''Serialization of a file to a dictionary object'''

        # File location is NOT retained because it can vary based on the local
        # configuration

        file_dict = {}
        file_dict['file_type'] = self.file_type.value
        file_dict['blob'] = base64.b64encode(self.binary_data)
        return file_dict

    def from_dict(self, file_dict):
        '''Deserialization of a file from a dictionary object'''
        self.encode_file(ndr.NdrConfigurationFiles(file_dict['file_type']),
                         base64.b64decode(file_dict['blob']))

class FileUpdateMessage(ndr.IngestMessage):
    '''Messages to update files on the recorder'''

    def __init__(self, config=None):
        self.config = config
        self.files = {}

        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.FILE_UPDATE)

    def create_report(self):
        '''Creates a status report message'''

        self.add_header('payload', self.to_dict())
        super().create_report()

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a Certificate Request record'''
        super().from_message(ingest_msg)
        self.from_dict(self.headers['payload'])
        return self

    def add_file(self, file_type: ndr.NdrConfigurationFiles, binary_data: bytes):
        '''Adds a file for inclusion to the update message.abs

        If file already exists in the class, it will be replaced'''

        file_object = FileObject(self.config)
        file_object.encode_file(file_type, binary_data)
        self.files[file_type] = file_object

    def write_updates(self):
        '''Writes configuration updates out'''

        if self.config is None:
            raise ValueError("Can't write files without configuration")

        for _, file_object in self.files.items():
            self.config.logger.info("Writing file: %s", file_object.file_location)
            file_object.write_file()

    def to_dict(self):
        '''Encode a message in dict form'''
        fu_msg_dict = {}

        fu_msg_dict['files'] = []
        for _, file_object in self.files.items():
            fu_msg_dict['files'].append(file_object.to_dict())
        return fu_msg_dict

    def from_dict(self, fu_msg_dict):
        '''Decode a message in dict form'''

        self.files = {}

        for file_dict in fu_msg_dict['files']:
            file_object = ndr.FileObject(self.config)
            file_object.from_dict(file_dict)

            self.files[file_object.file_type] = file_object
