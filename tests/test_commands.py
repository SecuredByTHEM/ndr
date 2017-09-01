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
import unittest.mock

import os
import sys

import ndr
import ndr.tools.syslog_uploader
import ndr.tools.status
import ndr.tools.alert_tester

import tests.util

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_SYSLOG_DATA = THIS_DIR + '/data/test_log.json'

class TestCommands(unittest.TestCase):
    '''Tests commands main functions'''
    def setUp(self):
        # To make pylint shutup
        self._ncc = None
        self._ndr_config_file = None
        self._created_files = []

        tests.util.setup_ndr_client_config(self)

    def tearDown(self):
        tests.util.cleanup_files(self)

    def test_writing_queue_message(self):
        '''Tests writing out a queue message and getting it back'''
        ingest_message = ndr.IngestMessage(
            self._ncc, ndr.IngestMessageTypes.TEST_ALERT
        )

        ingest_message.sign_report()
        ingest_message.load_into_queue()

        # Make sure there's only one file in the queue
        outbound_queue = os.listdir(self._ncc.outgoing_upload_spool)
        self.assertEqual(len(outbound_queue), 1)
        this_msg = self._ncc.outgoing_upload_spool + "/" + outbound_queue[0]

        loaded_msg = ndr.IngestMessage.verify_and_load_message(
            self._ncc, this_msg, only_accept_cn="ndr_test_suite")

        # This is slightly problematic because IngestMessages can't easily be compared to each other
        #
        # Yay for refactoring nightmares :/
        os.remove(this_msg)
        self.assertEqual(loaded_msg.message_type, ingest_message.message_type)

    def test_uploading_syslog(self):
        '''Tests syslog upload command'''
        syslog_uploader_cli = ["syslog_uploader", "-c", self._ndr_config_file, TEST_SYSLOG_DATA]
        with unittest.mock.patch.object(sys, 'argv', syslog_uploader_cli):
            ndr.tools.syslog_uploader.main()

        # Make sure there's only one file in the queue
        outbound_queue = os.listdir(self._ncc.outgoing_upload_spool)
        self.assertEqual(len(outbound_queue), 1)
        this_msg = self._ncc.outgoing_upload_spool + "/" + outbound_queue[0]

        loaded_msg = ndr.IngestMessage.verify_and_load_message(
            self._ncc, this_msg, only_accept_cn="ndr_test_suite")
        os.remove(this_msg)

        self.assertEqual(loaded_msg.message_type, ndr.IngestMessageTypes.SYSLOG_UPLOAD)
        syslog = ndr.SyslogUploadMessage().from_message(loaded_msg)

    def test_uploading_status(self):
        '''Tests uploading status messages'''
        status_uploader_cli = ["status_uploader", "-c", self._ndr_config_file]
        with unittest.mock.patch.object(sys, 'argv', status_uploader_cli):
            ndr.tools.status.main()

        # Make sure there's only one file in the queue
        outbound_queue = os.listdir(self._ncc.outgoing_upload_spool)
        self.assertEqual(len(outbound_queue), 1)
        this_msg = self._ncc.outgoing_upload_spool + "/" + outbound_queue[0]

        loaded_msg = ndr.IngestMessage.verify_and_load_message(
            self._ncc, this_msg, only_accept_cn="ndr_test_suite")
        os.remove(this_msg)

        self.assertEqual(loaded_msg.message_type, ndr.IngestMessageTypes.STATUS)

    def test_alert_tester(self):
        '''Tests alert tester messages'''
        alert_tester_cli = ["alert_tester", "-c", self._ndr_config_file]
        with unittest.mock.patch.object(sys, 'argv', alert_tester_cli):
            ndr.tools.alert_tester.main()

        # Make sure there's only one file in the queue
        outbound_queue = os.listdir(self._ncc.outgoing_upload_spool)
        self.assertEqual(len(outbound_queue), 1)
        this_msg = self._ncc.outgoing_upload_spool + "/" + outbound_queue[0]

        loaded_msg = ndr.IngestMessage.verify_and_load_message(
            self._ncc, this_msg, only_accept_cn="ndr_test_suite")
        os.remove(this_msg)

        self.assertEqual(loaded_msg.message_type, ndr.IngestMessageTypes.TEST_ALERT)
