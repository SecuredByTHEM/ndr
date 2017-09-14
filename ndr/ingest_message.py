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

'''ingest_message is the basic unit of messaging used by NDR.

This class controls the basic message format, and signing operations. Custom
message types should be derieved from it'''

import os
import tempfile
import subprocess
import logging
import time
import email.utils
import base64
import shutil

from enum import Enum
import yaml

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import ndr


class IngestMessage:

    '''Handles reporting to the ingest server'''

    def __init__(self, config=None, message_type=""):
        '''Creates an empty message, with mandatory headers already filled out.

        Attributes:
         - config: ndr.Config class instance; only required for sending/signing messages
                   can be set to None if simply decoding them
         - message_type: Sets who can understand the fields in the message_type
         '''

        self.generated_at = time.time()
        self.message_type = message_type

        self.headers = dict()

        # Initialize data we're generate in run
        self.config = config
        self.message = None
        self.signed_message = None

        # Messages by default go to the INCOMING queue
        self.upload_method = None
        self.destination = None
        self.destination_queue = IngestMessageDestinations.INCOMING_QUEUE

        if config is not None:
            self.upload_method = self.config.upload_method

    def from_message(self, old_msg):
        '''Handles the case of we need to instance ourselves from an existing message'''
        self.__dict__.update(old_msg.__dict__)

    def load_from_yaml(self, msg_yaml):
        '''Deserializes the YAML message into the base class and exposes the headers'''
        msg_dict = yaml.safe_load(msg_yaml)

        self.generated_at = email.utils.mktime_tz(
            email.utils.parsedate_tz(msg_dict.pop('generated-at')))
        self.message_type = IngestMessageTypes(msg_dict.pop('message-type'))

        self.headers = msg_dict

    def load_from_base64(self, b64_msg):
        '''Deserializes a base64-encoded YAML message'''
        return self.load_from_yaml(base64.decodebytes(b64_msg))

    def add_header(self, key, value):
        '''Adds a field to the message

        Headers common to all messages are automatically created at initialization time
        '''
        # FIXME: sanity check the value going in
        self.headers[key] = value

    def get_header(self, key):
        '''Returns a value from a parsed message'''
        return self.headers[key]

    def remove_header(self, key):
        '''Deletes a header'''
        del self.headers[key]

    def create_report(self):
        '''Creates a report similar to Internet Message Formating.

        The report is not automatically signed with S/MIME with this function'''

        # Start with the mandatory headers
        input_fields = {
            'version': 1,
            'generated-at': email.utils.formatdate(self.generated_at),
            'message-type': self.message_type.value,
        }

        # Add what we've collected
        input_fields.update(self.headers)
        message = yaml.dump(input_fields, default_flow_style=False)

        # Final newline at the end
        message += "\n"

        self.message = message

        return self.message

    def sign_report(self):
        '''Signs a report with the configured GPG key'''

        # Make sure we actually have a message before signing it
        if self.message is None:
            self.create_report()

        # Normally, I'd like to use a nice and shiny library for doing S/MIME signing, however
        # M2Crypto hasn't been ported to Python 3 yet (there's a branch for it but it looks
        # rather messy) so we're going to cheat here and simply sign with
        # openssl via S/MIME

        try:
            msg_fd, unsigned_msg = tempfile.mkstemp()
            os.write(msg_fd, bytes(self.message, 'utf-8'))
            os.close(msg_fd)
            msg_fd = 0

            openssl_cmd = ["openssl", "smime", "-sign", "-md", "sha256", "-in", unsigned_msg,
                           "-signer", self.config.ssl_certfile, "-inkey",
                           self.config.ssl_private_key, "-certfile", self.config.ssl_bundle,
                           "-text"]

            openssl_proc = subprocess.run(
                args=openssl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

            if openssl_proc.returncode != 0:
                raise ValueError(str(openssl_proc.stderr, 'utf-8'))

            self.signed_message = str(openssl_proc.stdout, 'utf-8')

        finally:
            if msg_fd != 0:
                os.close(msg_fd)
            os.remove(unsigned_msg)

    def derive_default_destination(self):
        '''Determines the destination if not explicately set'''
        if self.upload_method == 'local':
            if self.destination_queue == IngestMessageDestinations.ENROLLMENT_QUEUE:
                self.destination = self.config.outgoing_enrollment_spool
            elif self.destination_queue == IngestMessageDestinations.INCOMING_QUEUE:
                self.destination = self.config.outgoing_upload_spool
            else:
                raise ValueError(
                    "Unknown upload destination!", self.destination_queue.value)

        elif self.upload_method == 'uucp':
            if self.destination_queue == IngestMessageDestinations.ENROLLMENT_QUEUE:
                self.destination = self.config.enrollment_uucp_path
            elif self.destination_queue == IngestMessageDestinations.INCOMING_QUEUE:
                self.destination = self.config.ingest_uucp_path
            else:
                raise ValueError(
                    "Unknown upload destination!", self.destination_queue.value)
        elif self.upload_method == 'uux':
            # Destination is a bit different with uux, it's the command on the far-side that's
            # processing the message
            raise ValueError(
                "for uux transit, destination must be set by hand!")

    def load_into_queue(self):
        '''Loads the message into the UUCP queue for processing'''

        # If we're in the realm of sanity, we have both the UUCP host
        # address (which *should* be a single item, though we support,
        # passing through multiple bang paths if necessary), and the
        # location on the remote system to dump the file off in.
        #
        # We need to stick these things together with a bang and input
        # the signed report in place

        # Create a temporary file for UUCP to upload

        try:
            # mksftemp works via low level descriptors, and we
            # need exact control of when the file is written and
            # flushed. Unfortunately, you can't os.close() twice
            # so do the C approach and zero out the descriptor.
            #
            # FIXME: Find a better way

            msg_fd, uucp_upload = tempfile.mkstemp()
            os.write(msg_fd, bytes(self.signed_message, 'utf-8'))
            os.close(msg_fd)
            msg_fd = 0

            if self.destination is None:
                self.derive_default_destination()

            if self.upload_method == 'local':
                base_filename = os.path.basename(uucp_upload)
                shutil.copy(
                    uucp_upload, self.destination + "/" + base_filename)

            elif self.upload_method == 'uucp':
                uucp_command = ["/usr/bin/uucp", uucp_upload, self.destination]

                #logging.warn("UUCP command: %s", ' '.join(uucp_command))

                uucp_proc = subprocess.run(
                    args=uucp_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                if uucp_proc.returncode != 0:
                    logging.warn("UUCP return code: %d", uucp_proc.returncode)
                    raise ValueError  # FIXME: return actual error

            elif self.upload_method == 'uux':
                # Due to the fact that uux uses a seperate daemon, we need to change the
                # permissions so the uuxqt daemon can read the file

                os.chmod(uucp_upload, 0o644)

                # Glue the destination path to the command
                uux_path = self.destination + "!ndr-process-message"
                uux_command = ["/usr/bin/uux", "-C", uux_path, "!" + uucp_upload]
                logging.warn("UUX command: %s", ' '.join(uux_command))

                uux_proc = subprocess.run(
                    args=uux_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                if uux_proc.returncode != 0:
                    logging.error("UUX return code: %d", uux_proc.returncode)
                    logging.error(
                        "UUX said: %s", str(uux_proc.stderr, 'utf-8'))
                    raise ndr.UploadFailure(
                        uux_proc.returncode, str(uux_proc.stderr, 'utf-8'))
        finally:
            if msg_fd != 0:
                os.close(msg_fd)
            os.remove(uucp_upload)

    @staticmethod
    def verify_and_load_message(config, file, only_accept_cn=None):
        '''Checks the message's signature to make sure it was signed by someone in our CA chain'''
        try:
            # We need a temporary file to get the signer PEM
            msg_fd, signer_pem = tempfile.mkstemp()
            os.close(msg_fd)  # Don't need to write anything to it

            # CApath is required to force out any system CAs that might be in the global CNF file
            ossl_verify_cmd = ["openssl", "smime", "-verify",
                               "-in", file, "-CAfile", config.ssl_cafile,
                               "-CApath", "/dev/nonexistant-dir",
                               "-text", "-signer", signer_pem]

            ossl_verify_proc = subprocess.run(
                args=ossl_verify_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False)

            if ossl_verify_proc.returncode != 0:
                config.logger.warn(
                    "rejecting %s: %s", file, str(ossl_verify_proc.stderr))
                return None

            config.logger.info("%s passed openssl S/MIME verify", file)

            config.logger.debug("checking %s", signer_pem)
            with open(signer_pem, 'rb') as x509_signer:
                # NOW we can use cryptography to read the x509 certificates
                cert = x509.load_pem_x509_certificate(
                    x509_signer.read(), default_backend())

                common_name = cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME)[0].value

                config.logger.debug(
                    "signed message came from common name: %s", common_name)

            # Make sure the CN is something we're willing to accept
            if only_accept_cn is not None:
                if common_name != only_accept_cn:
                    config.logger.error("rejecting message due to CN %s != %s",
                                        common_name, only_accept_cn)

            # Read it in
            decoded_message = ossl_verify_proc.stdout
            message = IngestMessage(config)
            message.load_from_yaml(decoded_message)

            return message

        # and clean up after ourselves
        finally:
            os.remove(signer_pem)


class IngestMessageTypes(Enum):

    '''List of known message types'''
    ALERT_MSG = "alert_msg"
    STATUS = "status"
    CERTIFICATE_REQUEST = "cert_request"
    SYSLOG_UPLOAD = "syslog_upload"
    SNORT_TRAFFIC = "snort_traffic" # old-style SNORT traffic messages
    NMAP_SCAN = "nmap_scan"
    TEST_ALERT = "test_alert"
    REBOOT_REQUEST = "reboot_request"
    FILE_UPDATE = "file_update"
    TRAFFIC_REPORT = "traffic_report"


class IngestMessageDestinations(Enum):

    '''Places where a message can go'''
    INCOMING_QUEUE = "incoming"
    ENROLLMENT_QUEUE = "enrollment"
