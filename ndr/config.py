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

'''Handles configuration for NDR and holds global state variables such as the
logger variables'''

import os
import sys
import socket
import logging
import logging.handlers
import collections

import yaml

# pylint: disable=R0902
# The config method handles global state information from the config file
# and is used as a global object.

ImageInformation = collections.namedtuple(
    'ImageInformation', 'build_date image_type'
)

class Config:
    '''Handles global configuration information for NDR'''

    def __init__(self, yaml_file):
        '''Loads and initializes the client configuration class'''
        with open(yaml_file, 'r') as f:
            config_dict = yaml.safe_load(f)

        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
        logger = logging.getLogger(name=__name__)
        logger.setLevel(logging.DEBUG)

        #logger.propagate = False

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

        self.ndr_netconfig_file = config_dict.get('netcfg_file', '/persistant/etc/ndr/network_config.yml')

        if 'nmap' not in config_dict:
            config_dict['nmap'] = {}
        self.nmap_configuration_file = config_dict['nmap'].get('config', '/persistant/etc/ndr/nmap_config.yml')

        misc_dict = config_dict.get('misc', dict())

        self.image_information_file = misc_dict.get('image_info', "/etc/ndr/image_info.yml")
        self.tshark_ndr_binary = misc_dict.get('tshark_ndr', "/opt/tshark-ndr/bin/tshark")

    def to_dict(self):
        '''Outputs the config struct in dictionary form so it can be serialized. Used by the test suite'''
        config_dict = {}
        config_dict['hostname'] = self.hostname
        config_dict['ssl'] = {}
        config_dict['ssl']['keyfile'] = self.ssl_private_key
        config_dict['ssl']['bundle'] = self.ssl_bundle
        config_dict['ssl']['certfile'] = self.ssl_certfile
        config_dict['ssl']['csr'] = self.ssl_csr
        config_dict['ssl']['cafile'] = self.ssl_cafile
        config_dict['upload_method'] = self.upload_method
        config_dict['upload'] = {}
        if self.upload_method == "local":
            config_dict['upload']['incoming_directory'] = self.outgoing_upload_spool
            config_dict['upload']['enrollment_directory'] = self.outgoing_enrollment_spool
        elif self.upload_method == "uucp":
            config_dict['upload']['ingest_uucp_host'] = self.ingest_uucp_host
            config_dict['upload']['ingest_uucp_dir'] = self.ingest_uucp_dir
            config_dict['upload']['enrollment_uucp_dir'] = self.enrollment_uucp_dir
        config_dict['nmap'] = {}
        config_dict['nmap']['config'] = self.nmap_configuration_file

        config_dict['misc'] = {}
        config_dict['misc']['image_info'] = self.image_information_file
        config_dict['misc']['tshark_ndr_binary'] = self.tshark_ndr_binary
        return config_dict

    def get_image_version(self):
        '''Tries to load the image revision file'''
        try:
            with open(self.image_information_file, 'r') as ii_file:
                image_dict = yaml.safe_load(ii_file.read())
                image_info = ImageInformation(
                    build_date=image_dict['build_date'],
                    image_type=image_dict['image_type']
                )

                return image_info

        except: # pylint: disable=W0702
            self.logger.error('Failed to get image information file!')
            return None

    @property
    def ingest_uucp_path(self):
        '''Generates the Ingest UUCP path'''
        return self.ingest_uucp_host + "!" + self.ingest_uucp_dir

    @property
    def enrollment_uucp_path(self):
        '''Generates the enrollment UUCP path'''
        return self.ingest_uucp_host + "!" + self.enrollment_uucp_dir
