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

import os
import sys
import socket
import logging
import logging.handlers

import yaml

class Config:
    def __init__(self, yaml_file):
        '''Loads and initializes the client configuration class'''
        with open(yaml_file, 'r') as f:
            config_dict = yaml.safe_load(f)

        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
        logger = logging.getLogger(name=__name__)
        logger.setLevel(logging.DEBUG)

        logger.propagate = False

        # Only log to syslog if the socket exists (resolves build in chroot issue)
        if os.path.exists("/dev/log"):
            handler = logging.handlers.SysLogHandler(address='/dev/log')
            handler.ident = os.path.basename(sys.argv[0]) + " " # space required for syslog
            logger.addHandler(handler)

        self.logger = logger

        # Allow for overriding the hostname in the client configuration
        if 'hostname' in config_dict:
            self.hostname = config_dict['hostname']
        else:
            self.hostname = socket.gethostname()

        self.ssl_private_key = config_dict['ssl']['keyfile']
        self.ssl_bundle = config_dict['ssl']['bundle']
        self.ssl_certfile = config_dict['ssl']['certfile']
        self.ssl_csr = config_dict['ssl']['csr']
        self.ssl_cafile = config_dict['ssl']['cafile']

        self.nmap_scan_interface = config_dict['nmap']['scan_interface']

        self.upload_spool = None
        self.upload_method = config_dict['upload_method']

        #self.enlistment_timestamp_file = config_dict['enlistment_timestamp']
        #self.certificate_renewal_file = config_dict['certificate_renewal_timestamp']

        if self.upload_method == "local":
            self.outgoing_upload_spool = config_dict['upload']['incoming_directory']
            self.outgoing_enrollment_spool = config_dict['upload']['enrollment_directory']
        elif self.upload_method == "uucp":
            self.ingest_uucp_host = config_dict['upload']['ingest_uucp_host']
            self.ingest_uucp_dir = config_dict['upload']['ingest_uucp_dir']
            self.enrollment_uucp_dir = config_dict['upload']['enrollment_uucp_dir']
        else:
            raise ValueError("Unknown or missing upload method")

    @property
    def ingest_uucp_path(self):
        return self.ingest_uucp_host + "!" + self.ingest_uucp_dir

    @property
    def enrollment_uucp_path(self):
        return self.ingest_uucp_host + "!" + self.enrollment_uucp_dir