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
import tempfile
import ipaddress

from pyroute2 import IPRoute # pylint: disable=E0611

import ndr
import ndr_netcfg

# Testing data from a live system running syslog-ng in JSON reporting mode
THIS_DIR = os.path.dirname(os.path.abspath(__file__))


@unittest.skipIf(os.getuid() != 0, "must be root")
class TestNmapConfig(unittest.TestCase):

    '''Tests Nmap Configuration by creating a fake interface and confirming scan results'''

    def setUp(self):
        self._iproute = IPRoute()

        # Unfortunately, when creating dummy interfaces, you'll end up with an
        # interface named dummyX no matter what you do
        self._iproute.link('add', name='dummy0', kind='dummy')
        self._iproute.link('add', name='dummy1', kind='dummy')
        self._iproute.link('add', name='dummy2', kind='dummy')

        self._dummy0_idx = self._iproute.link_lookup(ifname='dummy0')[0]
        self._dummy1_idx = self._iproute.link_lookup(ifname='dummy1')[0]
        self._dummy2_idx = self._iproute.link_lookup(ifname='dummy2')[0]

        fd, self._scratch_config = tempfile.mkstemp()
        os.close(fd) # Don't need to write anything to it

        # We need to write out a configuration file so NmapConfig can read it
        netcfg = self.configure_interfaces(self._scratch_config)
        netcfg.export_configuration()

    def tearDown(self):
        # Remove our dummy interfaces
        self._iproute.link('remove', index=self._dummy0_idx)
        self._iproute.link('remove', index=self._dummy1_idx)
        self._iproute.link('remove', index=self._dummy2_idx)

        self._iproute.close()

        os.remove(self._scratch_config)

    # More or less copied and pasted from test_netcfg.py
    def configure_interfaces(self, config_file=None):
        '''Sets up interfaces for most tests'''

        nc = ndr_netcfg.NetworkConfiguration(config_file)
        nc.rename_interface("dummy0", "lan127")
        nc.set_configuration_method("lan127", ndr_netcfg.InterfaceConfigurationMethods.STATIC)
        nc.add_static_addr("lan127", "10.1.177.2", 24)

        nc.rename_interface("dummy1", "monitor234")
        nc.set_configuration_method("monitor234", ndr_netcfg.InterfaceConfigurationMethods.STATIC)
        nc.add_static_addr("monitor234", "10.2.177.2", 24)

        # Create an IPv6 enabled interface
        nc.rename_interface("dummy2", "lan322")
        nc.set_configuration_method("lan322", ndr_netcfg.InterfaceConfigurationMethods.STATIC)
        nc.add_static_addr("lan322", "192.168.17.2", 28)
        nc.add_static_addr("lan322", "fdd1:2013:2f69:388f::122", 64)

        nc.apply_configuration()
        return nc

    def test_scan_interfaces(self):
        '''Tests that we can properly only find the LAN interfaces any nothing else'''
        nmap_cfg = ndr.NmapConfig(self._scratch_config)

        self.assertIn("lan127", nmap_cfg.scan_interfaces)
        self.assertIn("lan322", nmap_cfg.scan_interfaces)
        self.assertNotIn("monitor234", nmap_cfg.scan_interfaces)

    def test_networks_to_scan(self):
        '''Tests that we determine the right CIDRs to scan'''

        nmap_cfg = ndr.NmapConfig(self._scratch_config)

        self.assertIn(ipaddress.ip_network("10.1.177.0/24"), nmap_cfg.networks_to_scan)
        self.assertIn(ipaddress.ip_network("192.168.17.0/28"), nmap_cfg.networks_to_scan)
        self.assertIn(ipaddress.ip_network("fdd1:2013:2f69:388f::/64"), nmap_cfg.networks_to_scan)
        self.assertNotIn(ipaddress.ip_network("10.2.177.0/24"), nmap_cfg.networks_to_scan)
