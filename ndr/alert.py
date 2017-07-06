# This file is part of NDR.
#
# Copyright (C) 2017 - Secured By THEM
# Original Author: Michael Casadevall <michaelc@them.com>
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

'''Alert messages are, as the name suggests, messages that generate
an alert upon upload. As of writing, they're only used for syslog
alerts but could be used for any sort of situational alert conditions'''

import ndr

class AlertMessage(ndr.IngestMessage):
    '''Creates status messages to the server'''
    def __init__(self, config=None):
        self.raised_by = ""

        # Would have called this message, but conflicts w/ the base class
        self.contents = ""
        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.ALERT_MSG)

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a Status message record'''
        super().from_message(ingest_msg)
        self.from_dict(self.headers['payload'])
        return self

    def create_report(self):
        '''Creates a status report message'''
        self.add_header('payload', self.to_dict())
        super().create_report()

    def to_dict(self):
        '''Prepares a status message for serialization.'''
        alert_dict = {}
        alert_dict['raised_by'] = self.raised_by
        alert_dict['contents'] = self.contents

        return alert_dict

    def from_dict(self, alert_dict):
        '''Deserializes the status message'''

        self.raised_by = alert_dict['raised_by']
        self.contents = alert_dict['contents']
