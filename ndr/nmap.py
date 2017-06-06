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

'''Handles representation and object manipulation of NMAP scan data, as well
as a runner class to handle calling out to NMAP. This class handles the
majority of data that comes out of NMAP but is by no means 100% complete.

As of right now, the following information is left on the table:
 - Script exectuion and run times
 - uptime determination
 - Traceroute information
 - TCP/IPID sequences
 - Information about the scan type run specifically
 - NMap settings information (retained)
 - SMURF attack data
   - I *really* want to incorporate this, but I can't actually find a vulerable
     host on my network as SMURF attacks are very very bad.
 - Probably other shit in the DTD

The following are known issues
 - NSE execution is in a ... less than friendly representation
   - See comment in NmapScriptOutput for related rant
 - There are probably ugly edge cases dealing with system merging
   and changes
 - The test code is getting close to the class size in length

This class should be tolernate of data it doesn't understand, but if you blow it up,
send a bug with the NMAP XML output and let me know!
'''

# pylint: disable=too-few-public-methods
import os
import ipaddress
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from enum import Enum

import yaml
import ndr
from ndr.utils import (set_dict_if_not_none,
                       set_value_if_dict_exists,
                       return_value_if_key_exists)


class NmapRunner(object):

    '''Runs NMAP scans on the network'''

    def __init__(self, config, interface):
        self.config = config
        self.interface = interface

    def scan(self, scan_type, options, networks):
        '''Does a IPv4 network scan'''

        xml_logfile = tempfile.mkstemp()

        # Invoke NMAP
        self.config.logger.info("== Running NMap Network Scan ==")

        self.config.logger.debug("Scanning Networks: %s", networks)
        self.config.logger.debug("Options: %s", options)

        # Build the full nmap command line
        nmap_cmd = ["nmap"]
        nmap_cmd += (options.split(" "))

        # Build in XML output
        nmap_cmd += ["-oX", xml_logfile[1]]
        nmap_cmd += [networks]

        self.config.logger.info("NMap Command: %s", ' '.join(nmap_cmd))

        nmap_proc = subprocess.run(
            args=nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

        if nmap_proc.returncode != 0:
            raise ndr.NmapFailure(nmap_proc.returncode,
                                  str(nmap_proc.stderr, 'utf-8'))

        xml_output = None
        with open(xml_logfile[1], 'r') as nmap_file:
            xml_output = nmap_file.read()
        os.remove(xml_logfile[1])

        # Build a scan object and return it
        nmap_scan = NmapScan(config=self.config)
        nmap_scan.parse_nmap_xml(xml_output)
        nmap_scan.scan_type = scan_type

        return nmap_scan

    def arp_host_discovery_scan(self, network):
        '''Performs a surface scan on the network'''
        return self.scan(NmapScanTypes.ARP_DISCOVERY, "-sn -PR", network)

    def v6_link_local_scan(self):
        '''Performs a link-local scan'''
        return self.scan(NmapScanTypes.IPV6_LINK_LOCAL_DISCOVERY, "-6 -sn -e %s --script=targets-ipv6-multicast-* --script-args=newtargets"
                         % (self.interface), "")

    def basic_host_scan(self, address):
        '''Does a basic port scan by hosts'''

        # Several bits of magic are required here
        # 1. If we're v6 address or range, we need -6
        # 2. If we're link-local, we need to specify the interface

        return self.scan(NmapScanTypes.PORT_SCAN, "-sS", address)

    def indepth_host_scan(self, address):
        '''Does a full discovery scan'''

        base_nmap_options = "-sS -A -T4"
        ipaddr = ipaddress.ip_address(address)

        options = base_nmap_options
        if ipaddr.version == 6:
            options = "-6 " + options
        if ipaddr.is_link_local:
            options = "-e " + self.interface + " " + options
        return self.scan(NmapScanTypes.SERVICE_DISCOVERY, options, str(address))


class NmapScan(ndr.IngestMessage):

    '''Repesents an object based view of a network scan, creating a basic map of the network'''

    def __init__(self, config=None):
        self.hosts = set()
        self.scan_type = None
        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.NMAP_SCAN)

    def __len__(self):
        return len(self.hosts)

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a NmapScan'''
        super().from_message(ingest_msg)
        self.from_dict(self.headers['payload'])
        return self

    def create_report(self):
        self.add_header('payload', self.to_dict())
        super().create_report()

    def parse_nmap_xml(self, xml):
        '''Parses an NMAP XML output file and generates a report based on it'''
        tree = ET.ElementTree(ET.fromstring(xml))
        root = tree.getroot()
        for child in root:

            if child.tag == "host":
                # Filter out offline IPs/hosts
                status = child.find("status")
                if status.attrib['state'] == "down":
                    continue

                # Hosts can be detected multiple times. We need to
                # filter out duplicates, and append any new information

                # Pass the child tag to the host
                host = NmapHost.from_xml(child)

                # Addreses can appear multiple times if they're successfully detected by
                # multiple methods
                #
                # This primarily happens due to loopback-detection, but can happen with multiple
                # overlapping scan results. As such we filter scan results by IP address so we
                # don't override previous results. This has the de-facto result that a host's
                # detection method will survive from first detected method

                self.hosts.add(host)

    def to_dict(self):
        '''Converts the scan results to dictionary form'''
        scan_dict = {}
        scan_dict['scan_type'] = self.scan_type.value
        scan_dict['hosts'] = []
        for host in self.hosts:
            scan_dict['hosts'].append(host.to_dict())
        return scan_dict

    def from_dict(self, scan_dict):
        '''Loads the scan results from dictionary form'''
        self.scan_type = NmapScanTypes(scan_dict['scan_type'])
        for host in scan_dict['hosts']:
            self.hosts.add(NmapHost.from_dict(host))

    def to_yaml(self):
        '''Writes the scan result as a YAML file'''

        # Dealing with YAML drives me sligtly batty, but whatcha going to do?
        return yaml.safe_dump(self.to_dict(), width=1000)

    @classmethod
    def from_yaml(cls, scan):
        '''Loads a scan from YAML'''
        scan_obj = NmapScan()
        scan_obj.from_dict(yaml.safe_load(scan))
        return scan_obj

    def find_by_mac(self, mac):
        '''Returns a list of host objects if found based on MAC

        Multiple hosts can have the same MAC due to multihoming considerations due to NMAP's
        concept of a host being a little unusual. Essentially a host is anything that has an IP
        address, and possibly a MAC address in addition'''

        found_hosts = []
        for host in self.hosts:
            if host.mac_address == mac:
                found_hosts.append(host)

        # Didn't find it
        if len(found_hosts) == 0:
            return None
        else:
            return found_hosts

    def find_by_ip(self, ip_str):
        '''Takes an IPv4 or IPv6 address and tries to match that to a host

        Returns NmapHost if found, else None
        '''

        ip_obj = ipaddress.ip_address(ip_str)
        for host in self.hosts:
            if host.addr == ip_obj:
                return host

        return None

    def full_ip_list(self):
        '''Returns a list of all IP addresses found in this scan'''

        full_ip_list = []
        for host in self.hosts:
            for address in host.addresses:
                if address.addrtype == NmapAddrTypes.IPV4 or address.addrtype == NmapAddrTypes.IPV6:
                    full_ip_list.append(address.addr)

        return full_ip_list

    def mac_to_ip_dict(self):
        '''Returns a dict of all MAC addresses seen within the scan and the addresses attached to
           those MACs. Used by NetworkDelta detection'''

        mac_to_ip = {}
        for host in self.hosts:
            if host.mac_address is None:
                continue

            mac = host.mac_address

            if mac not in mac_to_ip:
                mac_to_ip[mac] = []

            mac_to_ip[mac].append(host.addr)

        return mac_to_ip


class NmapHost(object):

    '''Represents a host in NMAP's view of the network'''

    def __init__(self, addr, state, reason, reason_ttl):
        self.state = state
        self.reason = NmapReasons(reason)
        self.reason_ttl = int(reason_ttl)
        self.addr = ipaddress.ip_address(addr)
        self.mac_address = None
        self.vendor = None
        self.hostnames = []
        self.ports = []
        self.osmatches = []

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __hash__(self):
        import json
        return hash(json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=True))

    @classmethod
    def from_xml(cls, xml):
        '''Initializes a host object from XML'''

        # According to nmap.dtd, we will always have at least one status
        # line which may or may not have the following attributes
        #
        # state (str)
        # reason (str)
        # reason_ttl (str)
        #
        # These should always be present no matter what

        status = xml.find("status")

        # Read in the address types that we know about
        addresses = xml.findall("address")

        if len(addresses) > 2:
            assert "Too many addresses in XML block!"

        addr = None
        mac_address = None
        vendor = None
        for address in addresses:
            # Vendor is optional
            if "vendor" in address.attrib:
                vendor = address.attrib['vendor']

            if (address.attrib['addrtype'] == NmapAddrTypes.IPV4.value
                    or address.attrib['addrtype'] == NmapAddrTypes.IPV6.value):
                addr = address.attrib['addr']
            elif address.attrib['addrtype'] == NmapAddrTypes.MAC.value:
                mac_address = address.attrib['addr']
                vendor = vendor

        host = cls(
            addr, status.attrib['state'], status.attrib['reason'], status.attrib['reason_ttl'])
        host.mac_address = mac_address
        host.vendor = vendor

        # Add hostnames
        hostnames_block = xml.find("hostnames")
        if hostnames_block is not None:
            # Walk the host attributes and do MAGIC
            for hostname in hostnames_block:
                host.hostnames.append(NmapHostname(
                    hostname.attrib['name'], hostname.attrib['type']))

        # Handle ports
        ports_block = xml.find("ports")
        if ports_block is not None:
            for port in ports_block.findall("port"):
                state = port.find("state")
                port_obj = NmapPort(
                    port.attrib['protocol'],
                    port.attrib['portid'],
                    state.attrib['state'],
                    state.attrib['reason'],
                    state.attrib['reason_ttl'])

                service_block = port.find("service")
                if service_block is not None:
                    service = NmapService(service_block.attrib['name'],
                                          service_block.attrib['conf'],
                                          service_block.attrib['method'])

                    xml_pv = service_block.attrib
                    service.tunnel = set_value_if_dict_exists(xml_pv, 'tunnel')
                    service.version = set_value_if_dict_exists(
                        xml_pv, 'version')
                    service.product = set_value_if_dict_exists(
                        xml_pv, 'product')
                    service.extrainfo = set_value_if_dict_exists(
                        xml_pv, 'extrainfo')

                    service.proto = set_value_if_dict_exists(xml_pv, 'proto')
                    service.rpcnum = set_value_if_dict_exists(xml_pv, 'rpcnum')
                    service.lowver = set_value_if_dict_exists(xml_pv, 'lowver')
                    service.highver = set_value_if_dict_exists(
                        xml_pv, 'highver')
                    service.ostype = set_value_if_dict_exists(xml_pv, 'ostype')
                    service.devicetype = set_value_if_dict_exists(
                        xml_pv, 'devicetype')
                    service.servicefp = set_value_if_dict_exists(
                        xml_pv, 'servicefp')

                    # Append any CPEs if we have them
                    for cpe in service_block.findall("cpe"):
                        service.cpes.append(cpe.text)

                    port_obj.service = service

                    # And for our last magic trick, get the output of scripts
                    for script in port.findall("script"):
                        n_script_output = NmapScriptOutput(script.attrib['id'],
                                                           script.attrib['output'])

                        # Elements are annoying, they can appear here or as part of
                        # a table. We'll handle the free floating ones, then append
                        # the tables at the end

                        n_script_output.handle_element(script)
                        # To make matters worse, elements might not have a key
                        # assigned to them making this extremely annoying
                        # Tables are much more annoying because they can
                        # recurse to infinite depth
                        n_script_output.handle_table(script)

                        port_obj.script_output.append(n_script_output)

                host.ports.append(port_obj)

        # Load OS detection information if we have it
        os_block = xml.find("os")
        if os_block is not None:
            # OS match is weird, we may have 0-infinity matches, so we need to
            # handle those cases
            for osmatch in os_block.findall("osmatch"):
                # DTD defines all elements of OSMatch MUST be there

                # We don't care about line which marks which lines in
                # nmap-os-match the hit was found
                nos = NmapOsMatch()
                nos.name = osmatch.attrib['name']
                nos.accuracy = osmatch.attrib['accuracy']

                # As a subclass of OsMatch is OsClass which is a more general representation of what
                # a device can be. It has several values which can be optional per the DTD so
                # we need to handle THAT too

                for osclass in osmatch.findall("osclass"):
                    # Optional values
                    osgen = None
                    ostype = None  # renamed from type in the DTD

                    if 'osgen' in osclass.attrib:
                        osgen = osclass.attrib['osgen']

                    if 'type' in osclass.attrib:
                        ostype = osclass.attrib['type']

                    noc = NmapOsClass()
                    noc.vendor = osclass.attrib['vendor']
                    noc.osgen = osgen
                    noc.ostype = ostype
                    noc.accuracy = osclass.attrib['accuracy']
                    noc.osfamily = osclass.attrib['osfamily']

                    # and because the fun times don't end there
                    for cpe in osclass.findall("cpe"):
                        noc.cpes.append(cpe.text)
                    nos.osclasses.append(noc)

                host.osmatches.append(nos)
        return host

    def to_dict(self):
        '''Represents the class as a dictionary for serialization'''

        host_dict = {}
        host_dict['state'] = self.state
        host_dict['reason'] = self.reason.value
        host_dict['reason_ttl'] = self.reason_ttl
        host_dict['addr'] = self.addr.compressed
        host_dict['mac_address'] = self.mac_address
        host_dict['vendor'] = self.vendor

        if len(self.hostnames) != 0:
            host_dict['hostnames'] = []
            for hostname in self.hostnames:
                host_dict['hostnames'].append(hostname.to_dict())

        if len(self.ports) != 0:
            host_dict['ports'] = []
            for port in self.ports:
                host_dict['ports'].append(port.to_dict())

        if len(self.osmatches) != 0:
            host_dict['osmatches'] = []
            for osmatch in self.osmatches:
                host_dict['osmatches'].append(osmatch.to_dict())

        return host_dict

    @classmethod
    def from_dict(cls, host_dict):
        '''Deserializes a host from dictionary representation'''
        this_host = NmapHost(
            host_dict['addr'],
            host_dict['state'],
            host_dict['reason'],
            host_dict['reason_ttl']
        )

        this_host.mac_address = host_dict['mac_address']
        this_host.vendor = host_dict['vendor']

        if "hostnames" in host_dict and host_dict['hostnames'] is not None:
            for hostname_dict in host_dict['hostnames']:
                this_host.hostnames.append(
                    NmapHostname.from_dict(hostname_dict)
                )

        if "ports" in host_dict and host_dict['ports'] is not None:
            for port_dict in host_dict['ports']:
                this_host.ports.append(
                    NmapPort.from_dict(port_dict)
                )

        if "osmatches" in host_dict and host_dict['osmatches'] is not None:
            for osmatch_dict in host_dict['osmatches']:
                this_host.osmatches.append(
                    NmapOsMatch.from_dict(osmatch_dict)
                )
        return this_host

    def has_hostname(self, other_hostname):
        '''Checks if a hostname is known to this host,

        If the hostname is a NmapHostname, type comparsion is also checked, otherwise,
        just the textual representation of the hostname is used'''

        if isinstance(other_hostname, NmapHostname):
            for hostname in self.hostnames:
                if hostname == other_hostname:
                    return True
        else:
            for hostname in self.hostnames:
                if hostname.hostname == other_hostname:
                    return True

        return False

    def get_open_port(self, other_port, other_protocol):
        '''Is a port open? If so, return service information about said port

        NOTE: this function will report false if the port wasn't scanned at all.
        '''

        for port in self.ports:
            if port.portid == other_port and port.protocol == other_protocol:
                return port

        return None

class NmapHostname(object):

    '''Represents an hostname within an NMap scan'''

    def __init__(self, hostname, hn_type):
        self.hostname = hostname
        self.type = NmapHostnameTypes(hn_type)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def to_dict(self):
        '''Represents the structure as a dict for serialization'''
        hostname_dict = {}
        hostname_dict['hostname'] = self.hostname
        hostname_dict['type'] = self.type.value
        return hostname_dict

    @classmethod
    def from_dict(cls, hostname_dict):
        '''Rebuilds the NmapHostname object from serialization'''
        return NmapHostname(
            hostname_dict['hostname'],
            hostname_dict['type']
        )


class NmapPort(object):

    '''Represents an NMAP port object in the DTD'''

    def __init__(self, protocol, portid, state, reason, reason_ttl):
        self.protocol = PortProtocols(protocol)
        self.portid = int(portid)
        self.state = NmapPortStates(state)
        self.reason = NmapReasons(reason)
        self.reason_ttl = int(reason_ttl)
        self.service = None
        self.script_output = []

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def to_dict(self):
        '''Repesents port information as a dict'''
        port_dict = {}
        port_dict['protocol'] = self.protocol.value
        port_dict['portid'] = self.portid
        port_dict['state'] = self.state.value
        port_dict['reason'] = self.reason.value
        port_dict['reason_ttl'] = self.reason_ttl

        if self.service is not None:
            port_dict['service'] = self.service.to_dict()

        if len(self.script_output) != 0:
            port_dict['script_output'] = []
            for script in self.script_output:
                port_dict['script_output'].append(script.to_dict())

        return port_dict

    @classmethod
    def from_dict(cls, port_dict):
        '''Deserializes NmapPort from a dict object'''
        this_port = NmapPort(
            port_dict['protocol'],
            port_dict['portid'],
            port_dict['state'],
            port_dict['reason'],
            port_dict['reason_ttl'])

        if 'service' in port_dict and port_dict['service'] is not None:
            this_port.service = NmapService.from_dict(port_dict['service'])

        if 'script_output' in port_dict and port_dict['script_output'] is not None:
            for script_output_dict in port_dict['script_output']:
                this_port.script_output.append(
                    NmapScriptOutput.from_dict(script_output_dict)
                )
        return this_port

    def find_script_output_by_id(self, other_name):
        '''Locates a NSE script by its id key'''
        for output in self.script_output:
            if output.script_name == other_name:
                return output

        return None

    def eq_by_proto(self, other):
        '''Determines if two ports are equal by their port and protocol numbers'''
        if self.portid == other.portid and self.protocol == other.protocol:
            return True
        return False


class NmapService(object):

    '''Represents a service detected by NMAP'''

    def __init__(self, name, confidence, method):
        self.name = name
        self.confidence = int(confidence)
        self.method = NmapServiceMethods(method)

        # Optional values
        self.version = None
        self.product = None
        self.extrainfo = None

        self.tunnel = None
        self.proto = None
        self._rpcnum = None
        self._lowver = None
        self._highver = None
        self.hostname = None
        self.ostype = None
        self.devicetype = None
        self.servicefp = None
        self.cpes = []

    @property
    def rpcnum(self):
        '''RPCNum is a numeric but optional value'''
        return self._rpcnum

    @rpcnum.setter
    def rpcnum(self, value):
        if value is None:
            self._rpcnum = None
            return
        self._rpcnum = int(value)

    @property
    def lowver(self):
        '''LowVer is used for RPC checking'''
        return self._lowver

    @lowver.setter
    def lowver(self, value):
        if value is None:
            self._lowver = None
            return
        self._rpcnum = int(value)

    @property
    def highver(self):
        '''High version is used for RPC checking'''
        return self._highver

    @highver.setter
    def highver(self, value):
        if value is None:
            self._highver = None
            return
        self._highver = int(value)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def to_dict(self):
        '''Convert object data to dict for serialization'''

        service_dict = {}

        # These fields should always be present
        service_dict['name'] = self.name
        service_dict['method'] = self.method.value
        service_dict['confidence'] = self.confidence

        set_dict_if_not_none(service_dict, 'version', self.version)
        set_dict_if_not_none(service_dict, 'product', self.product)
        set_dict_if_not_none(service_dict, 'extrainfo', self.extrainfo)

        set_dict_if_not_none(service_dict, 'tunnel', self.tunnel)
        set_dict_if_not_none(service_dict, 'proto', self.proto)
        set_dict_if_not_none(service_dict, 'rpcnum', self.rpcnum)
        set_dict_if_not_none(service_dict, 'lowver', self.lowver)
        set_dict_if_not_none(service_dict, 'highver', self.highver)
        set_dict_if_not_none(service_dict, 'hostname', self.hostname)
        set_dict_if_not_none(service_dict, 'ostype', self.ostype)
        set_dict_if_not_none(service_dict, 'devicetype', self.devicetype)
        set_dict_if_not_none(service_dict, 'servicefp', self.servicefp)

        if len(self.cpes) != 0:
            service_dict['cpes'] = self.cpes

        return service_dict

    @classmethod
    def from_dict(cls, service_dict):
        '''Converts a service dict back into NmapService'''
        this_service = NmapService(
            service_dict['name'],
            service_dict['confidence'],
            service_dict['method'])

        this_service.version = return_value_if_key_exists(
            service_dict, 'version')
        this_service.product = return_value_if_key_exists(
            service_dict, 'product')
        this_service.extrainfo = return_value_if_key_exists(
            service_dict, 'extrainfo')

        this_service.tunnel = return_value_if_key_exists(
            service_dict, 'tunnel')
        this_service.proto = return_value_if_key_exists(service_dict, 'proto')
        this_service.rpcnum = return_value_if_key_exists(
            service_dict, 'rpcnum')
        this_service.lowver = return_value_if_key_exists(
            service_dict, 'lowver')
        this_service.highver = return_value_if_key_exists(
            service_dict, 'highver')
        this_service.hostname = return_value_if_key_exists(
            service_dict, 'hostname')
        this_service.ostype = return_value_if_key_exists(
            service_dict, 'ostype')
        this_service.devicetype = return_value_if_key_exists(
            service_dict, 'devicetype')
        this_service.servicefp = return_value_if_key_exists(
            service_dict, 'servicefp')

        if 'cpes' in service_dict:
            for cpe in service_dict['cpes']:
                this_service.cpes.append(cpe)
        return this_service


class NmapScriptOutput(object):

    '''Represents script output from NMAP.

    Rant warning: The way this class works is very uninitive. I recommend checking the test code
    for an idea of how you interface with it. The basic problem is that NMAP (who's authors I
    have great respect for) is primarily built to be used by humans, and thus some of the
    functionality like XML output is relatively painful. The basic problem is that NSE scripts
    return data is a relatively free-form data in the form of keyed or unkeyed elem objects in
    the XML, and keys can overlap. As such, we need to try and work with this data in a way
    that makes at least some sense.

    In short, each unique element is stored in a list. If we get a key value, we store it
    as a dict with the key, followed by the element text. That allows us to retain both
    bits of information without being completely screwy. Elements can repeat key values,
    For example, see ssl-cert for this in action that return XML like this:

    <table>
        <elem key="value">CA:FALSE</elem>
        <elem key="critical">true</elem>
        <elem key="name">X509v3 Basic Constraints</elem>
    </table>
    <table>
        <elem key="value">12:AA:04:F6:4F:A8:01:F4:2B:CF:A9:DE:88:D1:93:8C:37:F7:AD:3E</elem>
        <elem key="name">X509v3 Subject Key Identifier</elem>
    </table>

    Not easy to worth with at all. At some point, we'll probably end up writing NSE probes that
    can convert said information into something more useful using the script_id field as a keying
    value and hoping for !collisions. Won't happen today though'''

    def __init__(self, script_name, output):
        self.script_name = script_name
        self.output = output
        self.elements = []

    def to_dict(self):
        script_output_dict = {}
        script_output_dict['script_name'] = self.script_name
        script_output_dict['output'] = self.output

        if self.elements is not None and len(self.elements) != 0:
            script_output_dict['elements'] = self.elements
        return script_output_dict

    @classmethod
    def from_dict(cls, script_output_dict):
        '''Deserializes from dict'''
        this_nso = NmapScriptOutput(
            script_output_dict['script_name'],
            script_output_dict['output']
        )

        if "elements" in script_output_dict:
            this_nso.elements = script_output_dict['elements']

        return this_nso

    def handle_element(self, element, append_to=None):
        # We can't set a default target to self so ...
        if append_to is None:
            append_to = self.elements

        for element in element.findall("elem"):
            if "key" in element.attrib:
                element_dict = {}
                element_dict[element.attrib['key']] = element.text
                append_to.append(element_dict)
            else:
                append_to.append(element.text)

    def handle_table(self, tables):
        for table in tables.findall("table"):
            # Check for subtables
            if table.find("table"):
                self.handle_table(table)

            table_list = []
            self.handle_element(table, table_list)

            if "key" in table.attrib:
                table_dict = {}
                table_dict[table.attrib['key']] = table_list
                self.elements.append(table_dict)
            else:
                self.elements.append(table_list)

    def find_by_id(self, other_id):
        '''Looks up a script id by id name'''
        for element in self.elements:
            if other_id in element:
                return element

        return None


class NmapOsMatch(object):

    '''Represents Operating System Detection Information'''

    def __init__(self):
        self.name = None
        self._accuracy = 0
        self.osclasses = []

    @property
    def accuracy(self):
        return self._accuracy

    @accuracy.setter
    def accuracy(self, value):
        self._accuracy = int(value)

    def to_dict(self):
        '''Converts OSMatch information to a dict for serialization'''
        osmatch_dict = {}
        osmatch_dict['name'] = self.name
        osmatch_dict['accuracy'] = self.accuracy

        if len(self.osclasses) != 0:
            osmatch_dict['osclasses'] = []
            for osclass in self.osclasses:
                osmatch_dict['osclasses'].append(
                    osclass.to_dict()
                )

        return osmatch_dict

    def load_dict(self, osmatch_dict):
        '''Reloads the structure with a dict object'''
        self.name = osmatch_dict['name']
        self.accuracy = osmatch_dict['accuracy']
        self.osclasses = []

        if 'osclasses' in osmatch_dict and osmatch_dict['osclasses'] is not None:
            for osclass_dict in osmatch_dict['osclasses']:
                self.osclasses.append(
                    NmapOsClass.from_dict(
                        osclass_dict
                    )
                )

    @classmethod
    def from_dict(cls, osmatch_dict):
        '''Creates OSMatch from dict from deserialization'''
        this_osmatch = NmapOsMatch()
        this_osmatch.load_dict(osmatch_dict)

        return this_osmatch


class NmapOsClass(object):
    # pylint: disable=too-many-arguments

    '''Represents the classes of operating system a device might be'''

    def __init__(self):
        self.vendor = None
        self.osgen = None  # optional
        self.ostype = None  # optional
        self._accuracy = 0
        self.osfamily = None
        self.cpes = []

    def to_dict(self):
        '''Represents NMap OSClass as a dict for serialization'''
        osclass_dict = {}

        osclass_dict['vendor'] = self.vendor
        if self.osgen is not None:
            osclass_dict['osgen'] = self.osgen
        if self.ostype is not None:
            osclass_dict['ostype'] = self.ostype
        osclass_dict['accuracy'] = self.accuracy
        osclass_dict['osfamily'] = self.osfamily

        if len(self.cpes) != 0:
            osclass_dict['cpes'] = []
            for cpe in self.cpes:
                osclass_dict['cpes'].append(cpe)

        return osclass_dict

    def load_dict(self, osclass_dict):
        '''This is seperated out to its own function for inhertiance reasons'''
        self.vendor = osclass_dict['vendor']
        self.osgen = return_value_if_key_exists(osclass_dict, 'osgen')
        self.ostype = return_value_if_key_exists(osclass_dict, 'ostype')
        self.accuracy = osclass_dict['accuracy']
        self.osfamily = osclass_dict['osfamily']

        self.cpes = []
        if 'cpes' in osclass_dict:
            for cpe in osclass_dict['cpes']:
                self.cpes.append(cpe)

    @classmethod
    def from_dict(cls, osclass_dict):
        '''Unpacks OsClass from dict form as part of deserialization'''
        this_osclass = NmapOsClass()
        this_osclass.load_dict(osclass_dict)

        return this_osclass

    @property
    def accuracy(self):
        return self._accuracy

    @accuracy.setter
    def accuracy(self, value):
        self._accuracy = int(value)


class PortProtocols(Enum):

    '''Port protocols are the way we successfully knocked on a port'''
    # pylint: disable=invalid-name
    IP = "ip"
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"


class NmapReasons(Enum):
    # From port-reasons.cc. The singular form is always used in the XML file, except
    # in extra reasons (we might need a second plural lookup table. Ugh)
    RESET = "reset"
    CONNECTION_REFUSED = "conn-refused",

    # Connection accepted is also listed as syn-ack
    SYN_ACK = "syn-ack"
    SPLIT_HANDSHAKE_SYN = "split-handshake-syn"
    UDP_RESPONSE = "udp-response"
    PROTOCOL_RESPONSE = "proto-response"
    PERMISSION_DENIED = "perm-denied"
    NETWORK_UNREACHABLE = "net-unreach"
    HOST_UNREACHABLE = "host-unreach"
    PROTOCOL_UNREACHABLE = "proto-unreach"
    ECHO_REPLY = "echo-reply"
    DESTINATION_UNREACHABLE = "dest-unreach"
    SOURCE_QUENCH = "source-quench"
    NET_PROHIBITED = "net-prohibited"
    HOST_PROHIBITED = "host-prohibited"
    ADMIN_PROHIBITED = "admin-prohibited"
    TIME_EXCEEDED = "time-exceeded"
    TIMESTAMP_REPLY = "timestamp-reply"
    NO_IPID_CHANGE = "no-ipid-change"
    ARP_RESPONSE = "arp-response"
    ND_RESPONSE = "nd-response"
    TCP_RESPONSE = "tcp-response"
    NO_RESPONSE = "no-response"
    INIT_ACK = "init-ack"
    ABORT = "abort"
    LOCALHOST_RESPONSE = "localhost-response"
    SCRIPT_SET = "script-set"
    UNKNOWN_RESPONSE = "unknown-response"
    USER_SET = "user-set"
    NO_ROUTE = "no-route"
    BEYOND_SCOPE = "beyond-scope"
    REJECT_ROUTE = "reject-route"
    PARAMETER_PROBLEM = "param-problem"


class NmapAddrTypes(Enum):

    '''AddrTypes as defined by nmap's DTD'''
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC = "mac"


class NmapPortStates(Enum):

    '''Port states - from nmap.cc statenum2str'''
    OPEN = "open"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    CLOSED = "closed"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNKNOWN = "unknown"


class NmapHostnameTypes(Enum):

    '''Hostname types as defined by nmap's DTD'''
    USER = "user"
    PTR = "PTR"


class NmapServiceMethods(Enum):

    '''Method on how services were probed by NMAP'''
    TABLE = "table"
    PROBED = "probed"

class NmapScanTypes(Enum):

    '''Types of scans we do with NMAP'''
    ARP_DISCOVERY = "arp-discovery"
    IPV6_LINK_LOCAL_DISCOVERY = 'ipv6-link-local-discovery'
    IP_PROTOCOL_DETECTION = "ip-protocol-detection"
    PORT_SCAN = "port-scan"
    SERVICE_DISCOVERY = "service-discovery"