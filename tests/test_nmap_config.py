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

import yaml

import ndr
import ndr_netcfg

# Testing data from a live system running syslog-ng in JSON reporting mode
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
NMAP_CONFIG = THIS_DIR + "/data/nmap_config.yml"

@unittest.skipIf(os.getuid() != 0, "must be root")
class TestNmapConfigRoot(unittest.TestCase):

    '''Tests Nmap Configuration by creating a fake interface and confirming scan results'''

    def setUp(self):
        self._iproute = IPRoute()

        self._iproute.link('add', ifname='lan127', kind='dummy')
        self._iproute.link('add', ifname='monitor234', kind='dummy')
        self._iproute.link('add', ifname='lan322', kind='dummy')

        self._dummy0_idx = self._iproute.link_lookup(ifname='lan127')[0]
        self._dummy1_idx = self._iproute.link_lookup(ifname='monitor234')[0]
        self._dummy2_idx = self._iproute.link_lookup(ifname='lan322')[0]

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
        nc.set_configuration_method("lan127", ndr_netcfg.InterfaceConfigurationMethods.STATIC)
        nc.add_static_addr("lan127", "10.1.177.2", 24)

        nc.set_configuration_method("monitor234", ndr_netcfg.InterfaceConfigurationMethods.STATIC)
        nc.add_static_addr("monitor234", "10.2.177.2", 24)

        # Create an IPv6 enabled interface
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

class TestNmapConfig(unittest.TestCase):
    '''Handles non-root tests for testing NMAP Config'''
    def setUp(self):
        fd, self._scratch_config = tempfile.mkstemp()
        os.close(fd) # Don't need to write anything to it

    def tearDown(self):
        os.remove(self._scratch_config)

    def test_to_dict(self):
        '''Tests serialization to dict'''
        nmap_cfg = ndr.NmapConfig(self._scratch_config)
        nmap_cfg.ip_address_config[ipaddress.ip_address("192.168.2.123")] = ndr.NmapScanMode.BASIC_ONLY
        nmap_cfg.ip_address_config[ipaddress.ip_address("192.168.10.21")] = ndr.NmapScanMode.BLACKLIST

        nmap_cfg.mac_address_config["FF:EE:CC:DD:EE:AA"] = ndr.NmapScanMode.BASIC_ONLY
        nmap_cfg.mac_address_config["AA:BB:CC:DD:EE:FF"] = ndr.NmapScanMode.BLACKLIST

        cfg_dict = nmap_cfg.to_dict()
        self.assertEqual(cfg_dict['version'], 1)
        self.assertEqual(cfg_dict['machine_ips']['192.168.2.123'], 'basic-only')
        self.assertEqual(cfg_dict['machine_ips']['192.168.10.21'], 'blacklist')
        self.assertEqual(cfg_dict['machine_macs']['FF:EE:CC:DD:EE:AA'], 'basic-only')
        self.assertEqual(cfg_dict['machine_macs']['AA:BB:CC:DD:EE:FF'], 'blacklist')

    def test_load_from_file(self):
        '''NMAP runner should load it's configuration right from the get go as the second arg'''
        nmap_cfg = ndr.NmapConfig(netcfg_file=self._scratch_config,
                                  nmap_cfgfile=NMAP_CONFIG)

        self.assertEqual(nmap_cfg.ip_address_config[ipaddress.ip_address("192.168.2.123")],
                         ndr.NmapScanMode.BASIC_ONLY)
        self.assertEqual(nmap_cfg.ip_address_config[ipaddress.ip_address("192.168.10.21")],
                         ndr.NmapScanMode.BLACKLIST)
        self.assertEqual(nmap_cfg.mac_address_config["FF:EE:CC:DD:EE:AA"],
                         ndr.NmapScanMode.BASIC_ONLY)
        self.assertEqual(nmap_cfg.mac_address_config["AA:BB:CC:DD:EE:FF"],
                         ndr.NmapScanMode.BLACKLIST)

    def test_write_to_file(self):
        '''Tests writing out the NMAP configuration to file'''
        fd, out_file = tempfile.mkstemp()
        os.close(fd) # Don't need to write anything to it

        nmap_cfg = ndr.NmapConfig(netcfg_file=self._scratch_config,
                                  nmap_cfgfile=out_file)

        nmap_cfg.ip_address_config[ipaddress.ip_address("192.168.2.123")] = ndr.NmapScanMode.BASIC_ONLY
        nmap_cfg.ip_address_config[ipaddress.ip_address("192.168.10.21")] = ndr.NmapScanMode.BLACKLIST

        nmap_cfg.mac_address_config["FF:EE:CC:DD:EE:AA"] = ndr.NmapScanMode.BASIC_ONLY
        nmap_cfg.mac_address_config["AA:BB:CC:DD:EE:FF"] = ndr.NmapScanMode.BLACKLIST
        nmap_cfg.write_configuration()

        # Read the config file back in as a YAML file
        with open(out_file, 'r') as f:
            contents = f.read()
            #print(contents)
            written_dict = yaml.safe_load(contents)

        self.assertEqual(written_dict, nmap_cfg.to_dict())
        os.remove(out_file)
