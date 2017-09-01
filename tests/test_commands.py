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
import ndr.tools.process_message

import tests.util

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_SYSLOG_DATA = THIS_DIR + '/data/test_log.json'
NMAP_CONFIG = THIS_DIR + "/data/nmap_config.yml"

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

    def test_process_message_file_update(self):
        '''Tests updating files via the file manager'''

        # Write out a file update message
        with open(NMAP_CONFIG, 'rb') as f:
            binary_data = f.read()

        # Write a file update message and drop it into the queue
        file_update_message = ndr.FileUpdateMessage(self._ncc)
        file_update_message.add_file(ndr.NdrConfigurationFiles.NMAP_CONFIG, binary_data)
        file_update_message.sign_report()
        file_update_message.load_into_queue()

        # Find the output message for chucking it into process-message
        outbound_queue = os.listdir(self._ncc.outgoing_upload_spool)
        self.assertEqual(len(outbound_queue), 1)
        this_msg = self._ncc.outgoing_upload_spool + "/" + outbound_queue[0]

        # Process da message
        process_msg_cli = ["ndr-process-message", "-c", self._ndr_config_file, this_msg]
        with unittest.mock.patch.object(sys, 'argv', process_msg_cli):
            with unittest.mock.patch('os.getuid') as uid:
                uid.return_value = 0
                ndr.tools.process_message.main()

        # Confirm the file actually got written out
        with open(self._ncc.nmap_configuration_file, 'rb') as f:
            written_file = f.read()

        self.assertEqual(binary_data, written_file)
