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

'''Certificate requests are used for both creating the initial SSL certificates
for S/MIME signing/Client auth, and renewal requests.'''

import os
from enum import Enum
import ndr

class CertificateRequest(ndr.IngestMessage):
    '''Certificate Requests'''
    def __init__(self, config=None):
        self.config = config

        self.csr = None
        self.certificate = None
        self.certificate_chain = None
        self.root_certificate = None

        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.CERTIFICATE_REQUEST)

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a SnortTraffic record'''
        super().from_message(ingest_msg)
        self.csr = self.headers['csr']
        self.certificate = self.headers['certificate']
        self.certificate_chain = self.headers['certificate_chain']
        self.root_certificate = self.headers['root_certificate']

        return self

    def create_report(self):
        self.add_header('csr', self.csr)
        self.add_header('certificate', self.certificate)
        self.add_header('certificate_chain', self.certificate_chain)
        self.add_header('root_certificate', self.root_certificate)
        super().create_report()

class CertificateRequestTypes(Enum):
    '''Indicates the type for certificate enlistment'''
    NEW_CERTIFICATE = "new_certificate"
    SIGNED_CERTIFICATE = "signed_certificate"
    RENEWAL = "renew"
