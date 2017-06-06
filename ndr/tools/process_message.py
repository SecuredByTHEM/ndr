#!/usr/bin/python3
# This file is part of NDR.
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

'''Processes an incoming message from uux'''

import os
import argparse
import shutil
import tempfile
import subprocess

import ndr


def main():
    # Get our list of log files
    parser = argparse.ArgumentParser(
        description="Process a remote message")
    parser.add_argument('-k', "--keep", help='base name of the log file to upload', action='store_true')
    parser.add_argument('messages', nargs='+',
                        help='remote messages to process')
    args = parser.parse_args()

    ndr_config = ndr.Config('/etc/ndr/config.yml')
    logger = ndr_config.logger

    validated_messages = []

    for message_file in args.messages:
        # DEBUG, write message to file
        if not os.path.isdir("/tmp/incoming_messages"):
            os.makedirs("/tmp/incoming_messages")
        logger.info("Processing %s", message_file)
        shutil.copy(
            message_file, "/tmp/incoming_messages/" + os.path.basename(message_file))

        # If we're operating in UUCP mode, then we only accept messages signed
        # by our ingest
        accepted_cns = None

        if ndr_config.upload_method == 'uucp':
            accepted_cns = ndr_config.ingest_uucp_host
        else:
            logger.warning("accepting any signed messages due to local mode!")

        message = ndr.IngestMessage.verify_and_load_message(
            ndr_config, message_file, only_accept_cn=accepted_cns)
        if message is not None:
            logger.info("Successfully parsed and validated the message!")

        # Now some magic is required. If we're running via uux, we're running in the context of
        # the uucp user and not under NDR. The UUCP user can run ndr-process-message as sudo so
        # we need to copy the message over to a temporary directory if we're not root, and then
        # recurse into ourselves. We'll do this for all the messages in the stack.
        validated_messages.append(message_file)

        # If we're root, just process it
        if os.getuid() == 0:
            logger.info("Running in root context")

            # Now do things with it based on the type of message it is
            if message.message_type == ndr.IngestMessageTypes.CERTIFICATE_REQUEST:
                logger.info("Got a certificate request message ...")

                cert_request_msg = ndr.CertificateRequest()
                cert_request_msg.from_message(message)

                # Write out the signed certificates to the root filesystem
                if cert_request_msg.certificate is not None:
                    logger.info("Writing out signed certificate ...")
                    with open(ndr_config.ssl_certfile, 'w') as f:
                        f.write(cert_request_msg.certificate)
                if cert_request_msg.certificate_chain is not None:
                    logger.info("Writing out certificate chain ...")
                    with open(ndr_config.ssl_bundle, 'w') as f:
                        f.write(cert_request_msg.certificate_chain)
                logger.info("Updated certificate chain for device")

            else:
                logger.error("Got non-client accepted %s message", message.message_type.value)
        else:
            logger.info("Not running as root, saving messages to run in sudo")

    # Non-root fall through. We should have a pile of validated messages
    if os.getuid() != 0:
        files_for_sudo = []
        for valid_message in validated_messages:
            # The messages will be revalidated on the second go around
            msg_fd, vm_file = tempfile.mkstemp()
            os.close(msg_fd)
            shutil.copy(valid_message, vm_file)
            files_for_sudo.append(vm_file)

        # Attempt to call ourselves via sudo
        sudo_process_message = [ "sudo", "ndr-process-message"]
        sudo_process_message += files_for_sudo

        # Here goes nothing
        sudo_proc = subprocess.run(
            args=sudo_process_message, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False)

        if sudo_proc.returncode != 0:
            logger.error("sudo run failed: %s", str(sudo_proc.stderr, 'utf-8'))
            return

        # And done (we log this here so it only prints once)
        logger.info("Finished processing messages")

    # Make a final loop through to clean up our files
    if args.keep is False:
        for message in args.messages:
            os.remove(message)

    return

if __name__ == "__main__":
    main()
