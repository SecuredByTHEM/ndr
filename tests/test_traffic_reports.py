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
import ipaddress

import tests.util
import ndr

# Testing data from a live system running syslog-ng in JSON reporting mode
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TSHARK_REPORT = THIS_DIR + "/data/tshark_report.csv"
TSHARK_PCAP = THIS_DIR + "/data/tshark_trm_test.pcap"

class TrafficReportTest(unittest.TestCase):
    '''Tests handling of snort traffic data reporting'''

    def setUp(self):
        # To make pylint shutup
        self._ncc = None
        self._ndr_config_file = None
        self._created_files = []

        tests.util.setup_ndr_client_config(self)

    def tearDown(self):
        tests.util.cleanup_files(self)

    def check_last_entry(self, last_entry):
        '''Checks the last entry in the CSV/PCAP file'''
        self.assertEqual(last_entry.protocol, ndr.PortProtocols.TCP)
        self.assertEqual(last_entry.src_address, ipaddress.ip_address("192.168.2.2"))
        self.assertEqual(last_entry.src_port, 39274)
        self.assertEqual(last_entry.src_hostname, "test-outbound.example")
        self.assertEqual(last_entry.dst_address, ipaddress.ip_address("104.16.111.18"))
        self.assertEqual(last_entry.dst_port, 443)
        self.assertEqual(last_entry.dst_hostname, "test-inbound.example")
        self.assertEqual(last_entry.rx_bytes, 60)
        self.assertEqual(last_entry.tx_bytes, 54)

    def test_deserialization_of_csv_test_data(self):
        '''Tests reading in individual lines of a pcap capture'''

        with open(TSHARK_REPORT, 'r') as f:
            trm = ndr.TrafficReportMessage()
            trm.parse_csv_file(f)
            self.assertEqual(len(trm.traffic_entries), 25)

        # With the way Traffic Report is coded, entries go in back to from; the last
        # entry in the CSV file will become the first entry out due to LIFO

        last_entry = trm.traffic_entries.pop()
        self.check_last_entry(last_entry)

    def test_serializing_deserializing_tr_message(self):
        '''Tests serializing/deserialization of a message'''
        with open(TSHARK_REPORT, 'r') as f:
            trm = ndr.TrafficReportMessage()
            trm.parse_csv_file(f)

        trm_dict = trm.to_dict()
        trm2 = ndr.TrafficReportMessage()
        trm2.from_dict(trm_dict)

        self.assertEqual(len(trm2.traffic_entries), 25)

        # With the way Traffic Report is coded, entries go in back to from; the last
        # entry in the CSV file will become the first entry out due to LIFO

        last_entry = trm2.traffic_entries.pop()
        self.check_last_entry(last_entry)

    def test_parsing_pcap(self):
        '''Tests parsing a pcap entry'''
        trm = ndr.TrafficReportMessage(self._ncc)
        trm.parse_pcap_file(TSHARK_PCAP)
        self.assertEqual(len(trm.traffic_entries), 25)

        last_entry = trm.traffic_entries.pop()

        # The PCAP file was used to generate the CSV file, but edited to put in source hostnames for
        # parsing. Forcibly set the src/dst hostname so the asserts pass
        self.assertIsNone(last_entry.dst_hostname)
        self.assertIsNone(last_entry.src_hostname)

        last_entry.src_hostname = "test-outbound.example"
        last_entry.dst_hostname = "test-inbound.example"
        self.check_last_entry(last_entry)
