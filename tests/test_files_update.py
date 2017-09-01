#!/usr/bin/python3
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

'''Tests running command binaries from NDR'''

import unittest
import os
import base64

import ndr
import tests.util

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
NMAP_CONFIG = THIS_DIR + "/data/nmap_config.yml"
TEST_SYSLOG_DATA = THIS_DIR + '/data/test_log.json'


class TestFileOperations(unittest.TestCase):
    '''Tests functions related to file object and file messages'''

    def setUp(self):
        # To make pylint shutup
        self._ncc = None
        self._ndr_config_file = None
        self._created_files = []

        tests.util.setup_ndr_client_config(self)

    def tearDown(self):
        tests.util.cleanup_files(self)

    def test_file_object_encoding_file(self):
        '''Tests encoding a binary file'''
        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_object = ndr.FileObject(self._ncc)
        file_object.encode_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)

        self.assertEqual(self._ncc.nmap_configuration_file,
                         file_object.file_location)
        self.assertEqual(file_object.file_type,
                         ndr.NdrConfigurationFiles.NMAP_CONFIG)
        self.assertEqual(binary_data, file_object.binary_data)

    def test_file_object_serialization(self):
        '''Tests serializing files as an object'''
        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_object = ndr.FileObject(self._ncc)
        file_object.encode_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)

        file_dict = file_object.to_dict()

        self.assertEqual(file_dict['file_type'],
                         ndr.NdrConfigurationFiles.NMAP_CONFIG.value)
        self.assertEqual(file_dict['blob'], base64.b64encode(binary_data))
        self.assertEqual(base64.b64decode(file_dict['blob']), binary_data)

    def test_file_object_deserialization(self):
        '''Tests deserialization a file object'''
        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_dict = {}
        file_dict['file_type'] = ndr.NdrConfigurationFiles.NMAP_CONFIG.value
        file_dict['blob'] = base64.b64encode(binary_data)

        file_object = ndr.FileObject(self._ncc)
        file_object.from_dict(file_dict)

        self.assertEqual(self._ncc.nmap_configuration_file,
                         file_object.file_location)
        self.assertEqual(file_object.file_type,
                         ndr.NdrConfigurationFiles.NMAP_CONFIG)
        self.assertEqual(binary_data, file_object.binary_data)

    def test_writing_file_out_when_nonexisting(self):
        '''Tests writing out a file when the destination file is non-existant'''
        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_object = ndr.FileObject(self._ncc)
        file_object.encode_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)
        file_object.write_file()

        with open(self._ncc.nmap_configuration_file, 'rb') as f:
            written_file = f.read()

        self.assertEqual(binary_data, written_file)

    def test_writing_out_files_when_existing(self):
        '''Confirm that we can successfully update a file if it's already existant'''

        # First, rerun the previous test
        self.test_writing_file_out_when_nonexisting()

        # We'll use the syslog test data since ATM we're not validating that the
        # file contents are correct

        with open(TEST_SYSLOG_DATA, 'rb') as f:
            new_binary_data = f.read()

        # Assert that our new data and the existing data mismatch
        with open(self._ncc.nmap_configuration_file, 'rb') as f:
            self.assertNotEqual(f.read(), new_binary_data)

        # Now build the binary object, write it out, and see if we get a match
        file_object = ndr.FileObject(self._ncc)
        file_object.encode_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, new_binary_data)
        file_object.write_file()

        with open(self._ncc.nmap_configuration_file, 'rb') as f:
            self.assertEqual(f.read(), new_binary_data)

    def test_file_message_loading(self):
        '''Tests creating a file update message and loading it'''

        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_update_message = ndr.FileUpdateMessage(self._ncc)
        file_update_message.add_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)

        self.assertEqual(len(file_update_message.files), 1)
        self.assertEqual(file_update_message.files[ndr.NdrConfigurationFiles.NMAP_CONFIG].file_type,
                         ndr.NdrConfigurationFiles.NMAP_CONFIG)
        self.assertEqual(file_update_message.files[ndr.NdrConfigurationFiles.NMAP_CONFIG].binary_data,
                         binary_data)

    def test_file_message_serialization(self):
        '''Tests serializing a file update message'''
        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_update_message = ndr.FileUpdateMessage(self._ncc)
        file_update_message.add_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)
        fu_dict = file_update_message.to_dict()

        self.assertEqual(len(fu_dict['files']), 1)
        nmap_update = fu_dict['files'][0]
        self.assertEqual(nmap_update['blob'], base64.b64encode(binary_data))
        self.assertEqual(nmap_update['file_type'], ndr.NdrConfigurationFiles.NMAP_CONFIG.value)

    def test_file_message_deserialization(self):
        '''Tests deserializing a file message object'''

        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_dict = {}
        file_dict['file_type'] = ndr.NdrConfigurationFiles.NMAP_CONFIG.value
        file_dict['blob'] = base64.b64encode(binary_data)


        fu_dict = {}
        fu_dict['files'] = [file_dict]

        fu_msg = ndr.FileUpdateMessage(self._ncc)
        fu_msg.from_dict(fu_dict)

        self.assertEqual(len(fu_msg.files), 1)
        nmap_blob = fu_msg.files[ndr.NdrConfigurationFiles.NMAP_CONFIG]

        self.assertEqual(self._ncc.nmap_configuration_file,
                         nmap_blob.file_location)
        self.assertEqual(nmap_blob.file_type,
                         ndr.NdrConfigurationFiles.NMAP_CONFIG)
        self.assertEqual(binary_data, nmap_blob.binary_data)

    def test_file_message_self_serialization_deserialization(self):
        '''Confirms that a FU message can serialize itself, and then deserialize itself'''

        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_update_message = ndr.FileUpdateMessage(self._ncc)
        file_update_message.add_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)
        fu_dict = file_update_message.to_dict()

        fu_deserial_msg = ndr.FileUpdateMessage(self._ncc)
        fu_deserial_msg.from_dict(fu_dict)

        self.assertEqual(len(fu_deserial_msg.files), 1)
        nmap_blob = fu_deserial_msg.files[ndr.NdrConfigurationFiles.NMAP_CONFIG]

        self.assertEqual(self._ncc.nmap_configuration_file,
                         nmap_blob.file_location)
        self.assertEqual(nmap_blob.file_type,
                         ndr.NdrConfigurationFiles.NMAP_CONFIG)
        self.assertEqual(binary_data, nmap_blob.binary_data)

    def test_writing_out_fu_files(self):
        '''Tests writing out FU files'''

        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        file_update_message = ndr.FileUpdateMessage(self._ncc)
        file_update_message.add_file(
            ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)
        file_update_message.write_updates()

        with open(self._ncc.nmap_configuration_file, 'rb') as f:
            written_file = f.read()

        self.assertEqual(binary_data, written_file)
