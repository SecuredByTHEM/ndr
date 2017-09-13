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
TSHARK_REPORT = THIS_DIR + "/data/tshark_report.csv"

class TrafficReportTest(unittest.TestCase):
    '''Tests handling of snort traffic data reporting'''

    def test_deserialization_of_csv_test_data(self):
        '''Tests reading in individual lines of a pcap capture'''

        with open(TSHARK_REPORT, 'r') as f:
            trm = ndr.TrafficReportMessage()
            trm.parse_csv_file(f)
            print(len(trm.traffic_entries))
