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

'''Utility functions for use in the test suite'''

import subprocess
import os
import tempfile
import shutil
import logging

import yaml
import ndr

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
NDR_CONFIG_FILE = THIS_DIR + '/data/test_config.yml'
IMAGE_CONFIG = THIS_DIR + '/data/image_info.yml'

def create_temp_file(self):
    '''Creates scratch files as we need them'''
    file_descriptor, filename = tempfile.mkstemp()
    os.close(file_descriptor) # Don't need to write anything to it

    self._created_files.append(filename)
    return filename

def config_ndr_for_signing_and_local_queue(self):
    '''Configs NDR for loopback testing'''
    root_certificate = create_temp_file(self)
    csr = create_temp_file(self)
    private_key = create_temp_file(self)

    # First create the client private key
    openssl_cmd = ["openssl", "genrsa", "-out", private_key]
    openssl_proc = subprocess.run(
        args=openssl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    if openssl_proc.returncode != 0:
        raise ValueError(str(openssl_proc.stderr, 'utf-8'))

    # Generate a root CSR
    openssl_cmd = ["openssl", "req", "-new", "-key", private_key, "-out", csr,
                   "-subj", "/C=US/ST=New York/L=New York/O=SbT/OU=testing/CN=ndr_test_suite"]

    openssl_proc = subprocess.run(
        args=openssl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    if openssl_proc.returncode != 0:
        raise ValueError(str(openssl_proc.stderr, 'utf-8'))

    # Sign the root
    openssl_cmd = ["openssl", "x509", "-req", "-days", "365", "-in", csr,
                   "-signkey", private_key, "-out", root_certificate]
    openssl_proc = subprocess.run(
        args=openssl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    if openssl_proc.returncode != 0:
        raise ValueError(str(openssl_proc.stderr, 'utf-8'))

    # Override the variables controlling NSC's certificates
    self._ncc.ssl_certfile = root_certificate

    # Bundle should technically be optional ...
    self._ncc.ssl_bundle = root_certificate
    self._ncc.ssl_cafile = root_certificate
    self._ncc.ssl_private_key = private_key
    self._ncc.ssl_csr = csr

    # Switch the UUCP configuration to local

    # Create some temporary directories
    upload_spool = tempfile.mkdtemp()
    enrollment_spool = tempfile.mkdtemp()

    self._ncc.upload_method = "local"
    self._ncc.outgoing_upload_spool = upload_spool
    self._ncc.enrollment_spool = enrollment_spool

def cleanup_after_ndr(self):
    os.remove(self._ncc.ssl_bundle)
    os.remove(self._ncc.ssl_private_key)
    os.remove(self._ncc.ssl_csr)
    shutil.rmtree(self._ncc.outgoing_upload_spool)
    shutil.rmtree(self._ncc.enrollment_spool)

def setup_ndr_client_config(self):
    logging.getLogger().addHandler(logging.NullHandler())
    self._ncc = ndr.Config(NDR_CONFIG_FILE)
    self._ncc.logger = logging.getLogger()
    self._ncc.image_information_file = IMAGE_CONFIG

    self._created_files = []
    config_ndr_for_signing_and_local_queue(self)

    # Create a temporary directory for handling config files that are optional but may get
    # written out or updated or something.

    self._ncc_config_dir = tempfile.mkdtemp()

    # Override optional config files with paths that won't conflict
    self._ncc.nmap_configuration_file = self._ncc_config_dir + "/nmap_config.yml"

    # Write out the test config for testing mainrun programs
    self._ndr_config_file = create_temp_file(self)
    with open(self._ndr_config_file, 'w') as f:
        yaml_content = yaml.dump(self._ncc.to_dict())
        f.write(yaml_content)

def cleanup_files(self):
    for filename in self._created_files:
        os.remove(filename)

    shutil.rmtree(self._ncc_config_dir)
