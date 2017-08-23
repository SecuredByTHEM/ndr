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

import unittest
import os
import time
import tempfile
import ndr

# Testing data from a live system running syslog-ng in JSON reporting mode
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
NDR_CONFIG = THIS_DIR + '/data/test_config.yml'
IMAGE_CONFIG = THIS_DIR + '/data/image_info.yml'
NMAP_CONFIG = THIS_DIR + "/data/nmap_config.yml"

class StatusTest(unittest.TestCase):
    '''Tests handling of status messages'''

    @classmethod
    def setUpClass(cls):
        '''Sets everything up for testing status messages'''
        cls._current_time = int(time.time())

        cls._ncc = ndr.Config(NDR_CONFIG)
        cls._ncc.image_information_file = IMAGE_CONFIG

        # Create a temporary file for the OTA timestamp
        file_descriptor, cls._ota_timestamp = tempfile.mkstemp()

        with os.fdopen(file_descriptor, 'w') as ts_file:
            ts_file.write(str(cls._current_time))

        cls._ncc.image_timestamp_file = cls._ota_timestamp

    @classmethod
    def tearDownClass(cls):
        '''Get's rid of the temp timestamp file'''
        os.remove(cls._ota_timestamp)

    def test_ota_version_read(self):
        '''Tests OTA reading in the config'''
        image_tuple = self._ncc.get_image_version()

        self.assertEqual(image_tuple.build_date, 1502855552)
        self.assertEqual(image_tuple.image_type, 'development')

    def test_dict_serialization_no_files(self):
        '''Tests exporting to dict form with no files'''

        # Override the config's file paths to non-existant ones
        self._ncc.nmap_configuration_file = "/nonexistant/nonexist"

        status_message = ndr.StatusMessage(self._ncc)
        status_message.populate_status_information()

        image_tuple = self._ncc.get_image_version()
        status_dict = status_message.to_dict()

        self.assertEqual(status_dict['image_build_date'], image_tuple.build_date)
        self.assertEqual(status_dict['image_type'], image_tuple.image_type)

        # The status file shouldn't be present so files revision should be an empty dict
        self.assertNotIn('config_file_versions', status_dict)

        # Get the hash of the NMAP configuration
    def test_dict_serialization_with_files(self):
        '''Tests serializing files with filepaths actually set'''

        self._ncc.nmap_configuration_file = NMAP_CONFIG

        status_message = ndr.StatusMessage(self._ncc)
        status_message.populate_status_information()

        image_tuple = self._ncc.get_image_version()
        status_dict = status_message.to_dict()

        self.assertEqual(status_dict['image_build_date'], image_tuple.build_date)
        self.assertEqual(status_dict['image_type'], image_tuple.image_type)

        nmap_config_hash = ndr.StatusMessage.hash_file(NMAP_CONFIG)
        self.assertEqual(status_dict['config_file_versions']['nmap_config'], nmap_config_hash)

    def test_dict_deserialization(self):
        '''Tests that a dict is properly deserialized'''

        status_dict = {}
        status_dict['image_build_date'] = self._current_time
        status_dict['image_type'] = 'testing'

        status_message = ndr.StatusMessage(self._ncc)
        status_message.from_dict(status_dict)

        self.assertEqual(status_message.image_build_date, self._current_time)
        self.assertEqual(status_message.image_type, 'testing')
