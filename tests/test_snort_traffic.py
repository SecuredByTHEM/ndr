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
import ndr

# Testing data from a live system running syslog-ng in JSON reporting mode
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SNORT_TRAFFIC_DATA = THIS_DIR + '/data/snort_all_traffic.csv'

class SnortTrafficTest(unittest.TestCase):
    '''Tests handling of snort traffic data reporting'''

    def check_output_dict(self, traffic_dict):
        '''Checks the serialization dict against known values'''
        # Let's check some of the values
        for entry in traffic_dict['consolated_traffic']:
            if entry['proto'] != 'tcp':
                continue

            self.assertEqual(entry['src'], '192.168.2.2')
            self.assertEqual(entry['dstport'], 22)
            self.assertEqual(entry['srcport'], 58724)
            self.assertEqual(entry['ethsrc'], '30:85:A9:3C:9D:99')
            self.assertEqual(entry['ethdst'], '84:39:BE:64:3F:E5')
            self.assertEqual(entry['rxpackets'], 48)
            self.assertEqual(entry['txpackets'], 40)

    def test_parsing(self):
        '''Tests parsing a Snort CSV file'''
        traffic_log = ndr.SnortTrafficLog()
        traffic_log.append_log(SNORT_TRAFFIC_DATA)
        self.assertEqual(len(traffic_log), 90)

    def test_consolation(self):
        '''Tests that we get expected consolated data'''
        traffic_log = ndr.SnortTrafficLog()
        traffic_log.append_log(SNORT_TRAFFIC_DATA)

        traffic_log.consolate()
        self.assertEqual(len(traffic_log.consolated_traffic), 2)

    def test_dict_serialization(self):
        '''Tests exporting to dict form'''
        traffic_log = ndr.SnortTrafficLog()
        traffic_log.append_log(SNORT_TRAFFIC_DATA)
        traffic_log.consolate()

        traffic_dict = traffic_log.to_dict()
        self.assertEqual(len(traffic_dict['consolated_traffic']), 2)
        self.check_output_dict(traffic_dict)

    def test_dict_deserialization(self):
        '''Tests that a dict is properly deserialized'''
        traffic_log = ndr.SnortTrafficLog()
        traffic_log.append_log(SNORT_TRAFFIC_DATA)
        traffic_log.consolate()

        traffic_dict = traffic_log.to_dict()

        deserialized_traffic_log = ndr.SnortTrafficLog()
        deserialized_traffic_log.from_dict(traffic_dict)

        self.assertEqual(len(deserialized_traffic_log.consolated_traffic), 2)
        self.check_output_dict(deserialized_traffic_log.to_dict())
