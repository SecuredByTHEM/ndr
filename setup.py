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

from setuptools import setup, find_packages

setup(
    name="ndr",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'pyyaml',
        'cryptography',
        'pyroute2'
    ],
    entry_points={
        'console_scripts': [
            'ndr-syslog-uploader = ndr.tools.syslog_uploader:main',
            'ndr-scan-network = ndr.tools.scan_network:main',
            'ndr-enlist = ndr.tools.enlist:main',
            'ndr-alert-tester = ndr.tools.alert_tester:main',
            'ndr-snort-trafic-uploader = ndr.tools.snort_traffic_uploader:main',
            'ndr-process-message = ndr.tools.process_message:main'
        ]
    },
    test_suite="tests"
)
