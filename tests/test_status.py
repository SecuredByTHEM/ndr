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

class StatusTest(unittest.TestCase):
    '''Tests handling of status messages'''

    @classmethod
    def setUpClass(cls):
        '''Sets everything up for testing status messages'''
        cls._current_time = int(time.time())

        cls._ncc = ndr.Config(NDR_CONFIG)

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
        config_ver = self._ncc.get_image_version()
        self.assertEqual(config_ver, self._current_time)

    def test_dict_serialization(self):
        '''Tests exporting to dict form'''
        status_message = ndr.StatusMessage(self._ncc)

    def test_dict_deserialization(self):
        '''Tests that a dict is properly deserialized'''
        status_message = ndr.StatusMessage(self._ncc)

    def check_output_dict(self, traffic_dict):
        '''Checks the serialization dict against known values'''
        # Let's check some of the values
        status_message = ndr.StatusMessage(self._ncc)
