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
import yaml

from ndr import SyslogUploadMessage, SyslogEntry

# Testing data from a live system running syslog-ng in JSON reporting mode
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_SYSLOG_DATA = THIS_DIR + '/data/test_log.json'
NDR_CONFIG = ndr.Config(THIS_DIR + '/data/test_config.yml')

class SyslogTest(unittest.TestCase):
    def test_syslog_loading(self):
        '''Tests in-depth behavior of syslog loading as we do it with syslog_upload'''

        # For NDR, syslogs are in JSON-like (its complicated, see sysload_uploader,
        # for the gorey details) that we want to read and load an entry for. This
        # function runs through a sample log and makes sure we get realistic RL
        # results

        log_upload = SyslogUploadMessage(NDR_CONFIG)

        entries = 0
        with open(TEST_SYSLOG_DATA, 'r') as f:
            for line in f:
                yaml_line = yaml.safe_load(line)
                entry = SyslogEntry.from_dict(yaml_line)
                log_upload.add_entry(entry)
                entries += 1

        # No exceptions, let's do some sanity checking
        # We should have an equal number of entries to lines
        self.assertEqual(entries, log_upload.count())

        # Compare each entry to the syslog and make sure reality matches
        with open(TEST_SYSLOG_DATA, 'r') as f:
            syslog_iterator = log_upload.__iter__()

            for line in f:
                log = next(syslog_iterator)
                yaml_line = yaml.safe_load(line)

                self.assertEqual(yaml_line['message'], log.message)
                self.assertEqual(yaml_line['program'], log.program)
                if "pid" in yaml_line:
                    self.assertEqual(yaml_line['pid'], log.pid)
                self.assertEqual(yaml_line['host'], log.host)
                self.assertEqual(yaml_line['timestamp'], log.timestamp)

                # A few values we store as enumerations, check against the values
                self.assertEqual(yaml_line['priority'], log.priority.value)
                self.assertEqual(yaml_line['facility'], log.facility.value)

if __name__ == "__main__":
    unittest.main()
