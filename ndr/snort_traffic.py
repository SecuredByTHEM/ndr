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
import ipaddress
import csv
import sys
import collections
import gc

import ndr
import ndr_netcfg

# For snort CSV files to properly parse, two config options must be set
# config utc (for UTC dates)
# config show_year (or start snort with -y)

# NOTE: the naming in this class is to be consistent with SNORT configurations
# options, hence the lack of spaces/underscores between things.

class SnortTrafficLog(ndr.IngestMessage):
    '''Represents a single log upload message of snort IP traffic'''
    def __init__(self, config=None):
        self.traffic_entries = []
        self.consolated_traffic = {}

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
        '''Prepares a SnortTrafficLog for serialization.

        Only consolated data is serialized. Run consolate() before this function'''

        traffic_log_dict = {}
        traffic_log_dict['consolated_traffic'] = []

        for _, entry in self.consolated_traffic.items():
            traffic_log_dict['consolated_traffic'].append(entry.to_dict())

        return traffic_log_dict


    def from_dict(self, traffic_dict):
        '''Deserializes a SnortTrafficLog'''
        consolated_traffic_dicts = traffic_dict['consolated_traffic']

        for entry in consolated_traffic_dicts:
            cte = SnortConsolatedTrafficEntry.from_dict(entry)
            self.update_or_append_cte(cte)

    def consolate(self):
        '''Consolates a traffic report into a summary of information on what was happening'''
        traffic_consolation = collections.OrderedDict()
        traffic_consolation_fullduplex = collections.OrderedDict()

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

            # And bump up the packet count
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

        # Now we create new CTEs and update ourselves
        for _, value in traffic_consolation_fullduplex.items():
            # Create a ConsolatedTrafficEntry object for this, then append it.
            cte = SnortConsolatedTrafficEntry().from_dict(value)
            self.update_or_append_cte(cte)

        # Finally, zero out the internal traffic reports
        self.traffic_entries = []
        gc.collect()

    def update_or_append_cte(self, new_cte):
        '''Updates or appends a CTE object to this traffic report'''

        dict_hash = new_cte.dict_key()
        inverse_dict_hash = new_cte.inverse_dict_key()

        if dict_hash in self.consolated_traffic:
            self.consolated_traffic[dict_hash].merge(new_cte)
            return

        # See if the inverse key is there
        elif inverse_dict_hash in self.consolated_traffic:
            self.consolated_traffic[inverse_dict_hash].merge(new_cte)
            return
        else:
            # Else add it
            self.consolated_traffic[dict_hash] = new_cte

    def append_log(self, logfile):
        '''Parses an individual log file, and appends it to this traffic log'''

        try:
            with open(logfile, 'r') as f:
                reader = csv.DictReader(f, ['timestamp',
                                            'proto',
                                            'src',
                                            'srcport',
                                            'dst',
                                            'dstport',
                                            'ethsrc',
                                            'ethdst',
                                            'ethlen',
                                            'tcpflags',
                                            'tcpseq'])
                for row in reader:
                    try:
                        traffic_entry = ndr.SnortTrafficEntry()
                        traffic_entry.from_csv(row)
                        self.traffic_entries.append(traffic_entry)
                    except ValueError:
                        self.config.logger.error("failed to parse %s in %s: %s",
                                                 row, logfile, sys.exc_info()[1])
                    except: # pylint: disable=W0702
                        self.config.logger.error("cataphoric error %s %s %s",
                                                 logfile, row, sys.exc_info()[0])
        finally:
            pass

class SnortConsolatedTrafficEntry(object):
    '''Entry of a summary of consolated traffic information'''
    def __init__(self):
        self.firstseen = None
        self.proto = None
        self.src = None
        self.dst = None
        self.ethsrc = None
        self.ethdst = None
        self.rxpackets = 0
        self.txpackets = 0

    def dict_key(self):
        '''Creates a hash of this object'''
        return hash(
            (self.proto, self.src, self.dst, self.ethsrc, self.ethdst)
        )

    def inverse_dict_key(self):
        '''Creates the inverted hash of this object'''
        return hash(
            (self.proto, self.dst, self.src, self.ethdst, self.ethsrc)
        )

    def is_match(self, other):
        '''Determines if the CTEs match each other in some way'''
        if (self.is_same(other) is True or
                self.is_inverse(other) is True):
            return True

        return False

    def is_same(self, other):
        '''Determines if a CTE is the same'''
        if (self.proto == other.proto and
                self.src == other.src and
                self.dst == other.dst and
                self.ethsrc == other.ethsrc and
                self.ethdst == other.ethdst):
            return True

        return False

    def is_inverse(self, other):
        '''Determines if a CTE is an invert of the other'''
        if (self.proto == other.proto and
                self.src == other.dst and
                self.dst == other.src and
                self.ethsrc == other.ethdst and
                self.ethdst == other.ethsrc):
            return True

        # Nope, not a match
        return False

    def merge(self, other):
        '''Merges two CTEs into one if they're equal to each other'''

        if self.is_same(other):
            self.rxpackets += other.rxpackets
            self.txpackets += other.txpackets
        elif self.is_inverse(other):
            self.rxpackets += other.txpackets
            self.txpackets += other.rxpackets
        else:
            raise ValueError("CTE objects are not the same or inverse of each other!")

        # Update first seen if it's older
        if other.firstseen < self.firstseen:
            self.firstseen = other.firstseen

    def to_dict(self):
        '''Creates a serialiable dict of the consolated traffic log'''
        cte_dict = {}
        cte_dict['firstseen'] = self.firstseen
        cte_dict['proto'] = self.proto.value
        cte_dict['src'] = self.src.compressed

        # Again, these values can be optional
        cte_dict['dst'] = self.dst.compressed

        cte_dict['ethsrc'] = self.ethsrc
        cte_dict['ethdst'] = self.ethdst
        cte_dict['rxpackets'] = self.rxpackets
        cte_dict['txpackets'] = self.txpackets
        return cte_dict

    @classmethod
    def from_dict(cls, cte_dict):
        '''Creates a consolated traffic entry from a dict'''
        cte = SnortConsolatedTrafficEntry()
        cte.firstseen = cte_dict['firstseen']
        cte.proto = ndr.PortProtocols(cte_dict['proto'])
        cte.src = ipaddress.ip_address(cte_dict['src'])

        cte.dst = ipaddress.ip_address(cte_dict['dst'])

        cte.ethsrc = cte_dict['ethsrc']
        cte.ethdst = cte_dict['ethdst']
        cte.rxpackets = int(cte_dict['rxpackets'])
        cte.txpackets = int(cte_dict['txpackets'])

        return cte

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
