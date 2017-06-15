#!/usr/bin/python3
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

'''Generates an enlistment request for this recorder'''

import os
import sys
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import ndr


def main():
    config = ndr.Config('/etc/ndr/config.yml')

    # Unlike the majority of NDR tools, this one is meant to run interactivity
    print("Network Data Recorder Enlistment Tool")
    print("Copyright (C) 2017 - Secured By THEM")

    if os.getuid() != 0:
        print("ERROR: This utility must be run as root!")
        sys.exit(-1)

    hostname = config.hostname
    print("Hostname: ", hostname)

    # Print out some helpful messages, then ask questions
    print('''
This script will automatically generate a certificate signing request
and other security keys for this recorder. The information used in the CSR
will be used to create an organization and site if necessary, and the pseudonym
will become the default human readable name used to refer to this recorder.

Manual processing of the CSR is required server side. After uploading the CSR,
we'll poll to wait for the CSR to be signed and downloaded. If you don't wish to
enlist this recorder now, press Ctrl-C

NOTE: Names are case sensitive!
''')

    got_info = False
    while got_info is False:
        organization = ""
        while organization == "":
            organization = input("Organization: ")
            if organization == "":
                print("Organization can not be blank!")

        org_unit = ""
        while org_unit == "":
            org_unit = input("Organization Unit/Site: ")
            if organization == "":
                org_unit("OU can not be blank!")

        pseudonym = ""
        while pseudonym == "":
            pseudonym = input("Pseudonym/Human Name: ")
            if organization == "":
                pseudonym("Pseudonym can not be blank!")

        print()
        print("=== CSR to be generated ===")
        print("Organization:", organization)
        print("Organization Unit (Site):", org_unit)
        print("Pseudonym (Human Name):", pseudonym)
        print("Common Name:", hostname)
        print()

        confirmation = input("Is this information correct? [N/y] ")
        if confirmation and confirmation.lower()[0] == 'y':
            got_info = True

    # Check if we have a private key
    print("STEP 1: Checking cryptography keys ...")
    key = None
    if os.path.isfile(config.ssl_private_key) is False:
        print("No private key found, generating. This may take some time ...")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        with open(config.ssl_private_key, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("Generated ", config.ssl_private_key)

    else:
        print("Have recorder private key")
        with open(config.ssl_private_key, "rb") as f:
            key = load_pem_private_key(
                f.read(), password=None, backend=default_backend())

    # Now generate a certificate signing request (we can always generate a new
    # one safely)
    print("STEP 2: Generating CSR ...")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
        x509.NameAttribute(NameOID.PSEUDONYM, pseudonym)
    ])).sign(key, hashes.SHA256(), default_backend())

    with open(config.ssl_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print("CSR written to ", config.ssl_csr)

    # Uploading the report is a bit different since we don't have a local certificate to sign it
    # with. First, let's create a CertificateRequest message

    csr_msg = ndr.CertificateRequest(config)
    csr_msg.csr = str(csr.public_bytes(serialization.Encoding.PEM), 'utf-8')

    csr_msg.destination_queue = ndr.IngestMessageDestinations.ENROLLMENT_QUEUE

    # Now we create the report, and load it into signed message and send it on
    # its way
    csr_msg.create_report()
    csr_msg.signed_message = csr_msg.message
    csr_msg.load_into_queue()

if __name__ == '__main__':
    main()
