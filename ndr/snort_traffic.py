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

'''Handles parsing snort CSV reports relating to network traffic'''
import datetime
import time
import ipaddress

import ndr

# For snort CSV files to properly parse, two config options must be set
# config utc (for UTC dates)
# config show_year (or start snort with -y)

class SnortTrafficLog(ndr.IngestMessage):
    '''Represents a single log upload message of snort IP traffic'''
    def __init__(self, config=None):
        self.traffic_entries = []
        self.consolated_traffic = []
        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.SNORT_TRAFFIC)

    def __len__(self):
        return len(self.traffic_entries)

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a SnortTraffic record'''
        super().from_message(ingest_msg)
        self.from_dict(self.headers['payload'])
        return self

    def create_report(self):
        self.add_header('payload', self.to_dict())
        super().create_report()

    def to_dict(self):
        '''Prepares a SnortTrafficLog for serialization'''
        traffic_log_dict = {}
        traffic_log_dict['consolated_traffic'] = []

        for entry in self.consolated_traffic:
            flattened_entry = entry

            # Convert the values from flat representations to types as approperate
            flattened_entry['proto'] = flattened_entry['proto'].value
            flattened_entry['src'] = flattened_entry['src'].compressed
            flattened_entry['dst'] = flattened_entry['dst'].compressed
            traffic_log_dict['consolated_traffic'].append(flattened_entry)

        return traffic_log_dict


    def from_dict(self, traffic_dict):
        '''Deserializes a SnortTrafficLog'''
        self.traffic_entries = []
        traffic_entries_dicts = traffic_dict['log']

        for entry in traffic_entries_dicts:
            ste = SnortTrafficEntry()
            ste.from_dict(entry)
            self.traffic_entries.append(ste)

    def consolate(self):
        '''Consolates a traffic report into a summary of information on what was happening and where'''
        traffic_consolation = {}
        traffic_consolation_fullduplex = {}

        for entry in self.traffic_entries:
            # We need to consolate based on where it's going, where it coming from, and protocol.
            # so we need to create a unique hash based on this information

            # For UDP ports, we don't care what the srcport is, just the dstport since it's not
            # stream based
            if entry.proto == ndr.PortProtocols.UDP:
                entry.srcport = None

            key = entry.proto.value + entry.src.compressed + str(entry.srcport) + entry.dst.compressed + str(entry.dstport) + entry.ethsrc + entry.ethdst

            # Create the key index if it doesn't exist
            if key not in traffic_consolation:
                traffic_consolation[key] = {}
                traffic_consolation[key]['firstseen'] = entry.timestamp
                traffic_consolation[key]['proto'] = entry.proto
                traffic_consolation[key]['src'] = entry.src
                traffic_consolation[key]['srcport'] = entry.srcport
                traffic_consolation[key]['dst'] = entry.dst
                traffic_consolation[key]['dstport'] = entry.dstport
                traffic_consolation[key]['ethsrc'] = entry.ethsrc
                traffic_consolation[key]['ethdst'] = entry.ethdst
                traffic_consolation[key]['packets'] = 0

            # Theorically, we should get everything "in order", but just in case
            if entry.timestamp < traffic_consolation[key]['firstseen']:
                traffic_consolation[key]['firstseen'] = entry.timestamp

            traffic_consolation[key]['packets'] += 1

        # Now we go through this a second time and match end to ends
        for key, entry in traffic_consolation.items():
            inverse_key = entry['proto'].value + entry['dst'].compressed + str(entry['dstport']) + entry['src'].compressed + str(entry['srcport']) + entry['ethdst'] + entry['ethsrc']

            # Create the key if we haven't seen this pair at all
            if key not in traffic_consolation_fullduplex and inverse_key not in traffic_consolation_fullduplex:
                traffic_consolation_fullduplex[key] = entry
                traffic_consolation_fullduplex[key]['rxpackets'] = 0

            # If we've seen the inverse key, continue as we already processed this record
            if inverse_key in traffic_consolation_fullduplex:
                continue

            traffic_consolation_fullduplex[key]['txpackets'] = traffic_consolation_fullduplex[key].pop('packets', 0)

            # Now get the RX packets from the other side
            if inverse_key in traffic_consolation:
                traffic_consolation_fullduplex[key]['rxpackets'] = traffic_consolation[inverse_key]['packets']
                if traffic_consolation[inverse_key]['firstseen'] < traffic_consolation_fullduplex[key]['firstseen']:
                     traffic_consolation_fullduplex[key]['firstseen'] = traffic_consolation[inverse_key]['firstseen']

            # Zero out the internal consolated traffic list, and copy it in
            self.consolated_traffic = []
            packets = 0
            for _, value in traffic_consolation_fullduplex.items():
                packets += value['rxpackets']
                packets += value['txpackets']
                self.consolated_traffic.append(value)

            print(packets)
class SnortTrafficEntry(object):
    '''Represents a single log message of snort traffic information'''
    def __init__(self):
        self.timestamp = None
        self.proto = None
        self.src = None
        self.srcport = None
        self.dst = None
        self.dstport = None
        self.ethsrc = None
        self.ethdst = None
        self.ethlen = None
        self.tcpflags = None
        self.tcpseq = None

    def from_csv(self, msg_dict):
        '''Does some pre-processing for the CSV for import'''

        # Snort's CSV logging function includes a tailing space that needs to be replaced
        # removed for the date to properly parse.

        dt_obj = datetime.datetime.strptime(msg_dict['timestamp'].strip(),
                                            "%m/%d/%y-%H:%M:%S.%f")
        msg_dict['timestamp'] = dt_obj.timestamp()
        msg_dict['ethlen'] = int(msg_dict['ethlen'], 16)

        # Several fields are optional. Set to None in that case
        if msg_dict['tcpseq'] == '':
            msg_dict['tcpseq'] = None

        if msg_dict['srcport'] == '':
            msg_dict['srcport'] = None

        if msg_dict['dstport'] == '':
            msg_dict['dstport'] = None

        # It's possible that SNORT failed to detect the port protocol (this can
        # primarily happen with IPv6 traffic). In this case, we'll set it as generic IP
        # PortProtocol

        if msg_dict['proto'] == '':
            msg_dict['proto'] = 'ip'

        # Convert protocol to lowercase so it can be converted down the line
        msg_dict['proto'] = msg_dict['proto'].lower()
        # tcpseq is both optional and needs a value conversion
        if msg_dict['tcpseq'] is not None:
            msg_dict['tcpseq'] = int(msg_dict['tcpseq'], 16)

        return self.from_dict(msg_dict)

    def from_dict(self, msg_dict):
        '''Converts the entry back to dict format'''
        self.timestamp = msg_dict['timestamp']
        self.proto = ndr.PortProtocols(msg_dict['proto'])
        self.src = ipaddress.ip_address(msg_dict['src'])

        if msg_dict['srcport'] is not None:
            self.srcport = int(msg_dict['srcport'])

        self.dst = ipaddress.ip_address(msg_dict['dst'])

        if msg_dict['dstport'] is not None:
            self.dstport = int(msg_dict['dstport'])

        self.ethsrc = msg_dict['ethsrc']
        self.ethdst = msg_dict['ethdst']
        self.ethlen = int(msg_dict['ethlen'])
        self.tcpflags = msg_dict['tcpflags']

        if 'tcpseq' is not None:
            self.tcpseq = msg_dict['tcpseq']
        else:
            self.tcpseq = None

    def to_dict(self):
        '''Converts the entry to dict format for serialization'''
        traffic_entry = {}
        traffic_entry['timestamp'] = self.timestamp
        traffic_entry['proto'] = self.proto.value
        traffic_entry['src'] = self.src.compressed
        traffic_entry['srcport'] = int(self.srcport)
        traffic_entry['dst'] = self.dst.compressed
        traffic_entry['dstport'] = int(self.dstport)
        traffic_entry['ethsrc'] = self.ethsrc
        traffic_entry['ethdst'] = self.ethdst
        traffic_entry['ethlen'] = int(self.ethlen)
        traffic_entry['tcpflags'] = self.tcpflags
        traffic_entry['tcpseq'] = int(self.tcpseq)
        return traffic_entry