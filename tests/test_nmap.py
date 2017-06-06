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

'''Tests functionality related to the NMAP parser and scan runner'''

import unittest
import os
import ipaddress
import ndr

# Testing data from a live system running syslog-ng in JSON reporting mode
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_SURFACE_SCAN_DATA = THIS_DIR + '/data/nmap_v4_surface.xml'
TEST_V6_LINK_LOCAL_SCAN_DATA = THIS_DIR + '/data/nmap_v6_link_local.xml'
TEST_HOSTNAME_SCAN_DATA = THIS_DIR + '/data/nmap_hostname_test.xml'
TEST_SD_SCAN_DATA = THIS_DIR + '/data/nmap_service_discovery.xml'
TEST_MULTIHOME_DATA = THIS_DIR + '/data/nmap_multihome.xml'
TEST_MULTIHOME_V6_DATA = THIS_DIR + '/data/nmap_multihome_v6.xml'
NDR_CONFIG = ndr.Config(THIS_DIR + '/data/test_config.yml')


def load_nmap_xml_data(file_name):
    '''Helper function to load XML data'''
    with open(file_name, 'r') as xml_file:
        return xml_file.read()

class NmapTest(unittest.TestCase):
    '''Tests functionality related to NMAP scanning and parsing'''

    maxDiff = None

    def test_scandata_parsing(self):
        '''Tests parsing of the basic surface scan'''
        scan = ndr.NmapScan()

        scan.parse_nmap_xml(load_nmap_xml_data(TEST_SURFACE_SCAN_DATA))
        self.assertEqual(5, len(scan))

        # Got three hosts, find a host by MAC address
        host = scan.find_by_mac('84:39:BE:64:3F:E5')[0]

        # SHould only find one IP address
        self.assertNotEqual(None, host)

        self.assertTrue(host.addr, ipaddress.ip_address("192.168.2.100"))
        self.assertEqual(host.reason, ndr.NmapReasons.ARP_RESPONSE)

        # Confirm that we're not finding phantom hosts
        self.assertEqual(scan.find_by_mac('NOT_A_REAL_MAC'), None)

    def test_ipv6_linklocal_parsing(self):
        '''Tests the results of the IPv6 link-local scan'''

        scan = ndr.NmapScan()
        scan.parse_nmap_xml(load_nmap_xml_data(TEST_V6_LINK_LOCAL_SCAN_DATA))

        self.assertEqual(3, len(scan))

        # Got three hosts, find a host by MAC address
        host_list = scan.find_by_mac('84:39:BE:64:3F:E5')

        # SHould only find one IP address
        self.assertEqual(len(host_list), 1)

        host = host_list[0]
        self.assertTrue(host.reason, ndr.NmapReasons.ND_RESPONSE)
        self.assertEqual(host.addr, ipaddress.ip_address("fe80::8639:beff:fe64:3fe5"))

    def test_hostname_resolution(self):
        '''Tests the scanning of hostname and rDNS data'''

        hostname_scan = ndr.NmapScan()
        hostname_scan.parse_nmap_xml(load_nmap_xml_data(TEST_HOSTNAME_SCAN_DATA))

        host = hostname_scan.hosts.pop()
        self.assertTrue(host.has_hostname("soylentnews.org"))
        self.assertTrue(host.has_hostname("li941-192.members.linode.com"))
        self.assertFalse(host.has_hostname("not-sn.org"))

        # Test hostname obj comparsion
        sn_hostname = ndr.NmapHostname(
            "soylentnews.org", ndr.NmapHostnameTypes.USER)
        sn_hostname_ptr = ndr.NmapHostname(
            "soylentnews.org", ndr.NmapHostnameTypes.PTR)  # shouldn't match
        li694_hostname = ndr.NmapHostname(
            "li941-192.members.linode.com", ndr.NmapHostnameTypes.PTR)

        self.assertTrue(host.has_hostname(sn_hostname))
        self.assertFalse(host.has_hostname(sn_hostname_ptr))
        self.assertTrue(host.has_hostname(li694_hostname))

    def test_port_detection(self):
        '''Ensures that port detection information is actually there'''
        # We have two types of scans with port information in them, let's test them.

        port_info_scan = ndr.NmapScan()
        port_info_scan.parse_nmap_xml(load_nmap_xml_data(TEST_V6_LINK_LOCAL_SCAN_DATA))
        host = port_info_scan.find_by_mac('84:39:BE:64:3F:E5')[0]

        self.assertIsNotNone(host)

        self.assertIsInstance(host.get_open_port(22, ndr.PortProtocols.TCP), ndr.NmapPort)
        self.assertIsInstance(host.get_open_port(25, ndr.PortProtocols.TCP), ndr.NmapPort)
        self.assertIsNone(host.get_open_port(22, ndr.PortProtocols.UDP))

    def test_operating_system_detection(self):
        '''Determine via best guess of what operating system a device may or may not be running'''

        port_info_scan = ndr.NmapScan()
        port_info_scan.parse_nmap_xml(load_nmap_xml_data(TEST_SD_SCAN_DATA))
        host = port_info_scan.find_by_ip("72.14.184.41")

        self.assertIsNotNone(host)
        self.assertIsNotNone(host.osmatches)
        self.assertEqual(len(host.osmatches), 1)
        self.assertEqual(host.osmatches[0].name, "Linux 3.11 - 4.1")
        self.assertEqual(host.osmatches[0].accuracy, 100)

        osclass = host.osmatches[0].osclasses[0]

        self.assertEqual(osclass.ostype, "general purpose")
        self.assertEqual(osclass.vendor, "Linux")

        self.assertEqual(osclass.cpes[0], "cpe:/o:linux:linux_kernel:3")

    def test_service_discovery(self):
        '''Tests functioning of NmapService code'''

        sd_scan = ndr.NmapScan()
        sd_scan.parse_nmap_xml(load_nmap_xml_data(TEST_SD_SCAN_DATA))

        host = sd_scan.find_by_ip("72.14.184.41")

        self.assertIsNotNone(host)

        # Test sercured SMTP
        port_obj = host.get_open_port(465, ndr.PortProtocols.TCP)
        self.assertIsInstance(port_obj, ndr.NmapPort)

        # Port 465 should be running postfix
        self.assertEqual(port_obj.service.name, "smtp")
        self.assertEqual(port_obj.service.product, "Postfix smtpd")
        self.assertEqual(port_obj.service.tunnel, "ssl")
        self.assertEqual(port_obj.service.method, ndr.NmapServiceMethods.PROBED)
        self.assertEqual(port_obj.service.confidence, 10)

        # Make sure other values are none
        self.assertIsNone(port_obj.service.rpcnum)

        # Confirm the CPE is there and what we expect
        self.assertEqual(port_obj.service.cpes[0], "cpe:/a:postfix:postfix")

        # Check the script element data on this port
        self.assertIsNone(port_obj.find_script_output_by_id("not-a-real-id"))
        script = port_obj.find_script_output_by_id("smtp-commands")
        self.assertIsNotNone(script)
        self.assertEqual(script.output, "mail.soylentnews.org, PIPELINING, SIZE 10240000, ETRN, AUTH PLAIN LOGIN, AUTH=PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, ")

        # Now try getting some elements
        script = port_obj.find_script_output_by_id("ssl-cert")

        # Ugh, this horrid, see rant in nmap.py
        self.assertEqual(script.elements[1]['md5'], '66f70512e57e801e8c54f8956c808ddf')

    def test_yaml_serialization_deserialization(self):
        '''Tests that we can successfully serialize and deserialize the NMap scans'''

        sd_scan = ndr.NmapScan()
        sd_scan.scan_type = ndr.NmapScanTypes.SERVICE_DISCOVERY
        sd_scan.parse_nmap_xml(load_nmap_xml_data(TEST_SD_SCAN_DATA))
        sd_yaml = sd_scan.to_yaml()

        sd_scan2 = ndr.NmapScan.from_yaml(sd_yaml)
        sd_scan2.scan_type = ndr.NmapScanTypes.SERVICE_DISCOVERY

        # Because we don't have a recursive __eq__ mechanism in place
        # yet, reserialize the YAML and see if it equals
        self.assertEqual(sd_yaml, sd_scan2.to_yaml())

    def test_host_hash(self):
        sd_scan = ndr.NmapScan()
        sd_scan.scan_type = ndr.NmapScanTypes.SERVICE_DISCOVERY
        sd_scan.parse_nmap_xml(load_nmap_xml_data(TEST_SD_SCAN_DATA))

        sd_yaml = sd_scan.to_yaml()
        sd_scan2 = ndr.NmapScan.from_yaml(sd_yaml)

        host1 = sd_scan.hosts.pop()
        host2 = sd_scan2.hosts.pop()
        self.assertEqual(host1, host2)

'''    def test_mac_to_ip(self):
        multihome_scan = ndr.NmapScan()
        multihome_scan.parse_nmap_xml(load_nmap_xml_data(TEST_MULTIHOME_DATA))

        # This test data is slightly misnamed. It's a link-local scan from windsor that can see
        # the multihomed NIC adapter on perdition. I'll prpbably need to add more multihome IPv6
        # tests but this is good enough for now

        v6_link_local = ndr.NmapScan()
        v6_link_local.parse_nmap_xml(load_nmap_xml_data(TEST_MULTIHOME_V6_DATA))

        multihome_scan.merge(v6_link_local)

        ip_lookup_dict = multihome_scan.mac_to_ip_dict()
        self.assertEqual(len(ip_lookup_dict['30:85:A9:3C:9D:99']), 3)
'''