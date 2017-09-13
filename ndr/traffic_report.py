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

'''V2 traffic reports based on TCPdump vs. wireshark'''

import datetime
import ipaddress
import csv
import sys
import collections
import gc

import ndr
import ndr_netcfg

class TrafficReportMessage(ndr.IngestMessage):
    '''Represents a single log upload message of snort IP traffic'''
    def __init__(self, config=None):
        self.traffic_entries = []
        self.consolated_traffic = {}

        ndr.IngestMessage.__init__(
            self, config, ndr.IngestMessageTypes.TRAFFIC_REPORT)

    def __len__(self):
        return len(self.traffic_entries)

    def from_message(self, ingest_msg: ndr.IngestMessage):
        '''Converts an ingest message to a TrafficReport record'''
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
        pass

    def parse_pcap_file(self, logfile):
        '''Parses a pcap file with tshark-csv and spit out a CSV file'''
        pass

    def parse_csv_file(self, fileobj):
        '''Parses an individual log file, and appends it to this traffic log'''

        try:
            reader = csv.DictReader(fileobj, ['protocol',
                                              'src_addr',
                                              'src_hostname',
                                              'src_port',
                                              'dst_addr',
                                              'dst_hostname',
                                              'dst_port',
                                              'rx_frames',
                                              'rx_bytes',
                                              'tx_frames',
                                              'tx_bytes',
                                              'total_frames',
                                              'total_bytes',
                                              'start_time',
                                              'duration'])
            for row in reader:
                try:
                    traffic_entry = ndr.TsharkCsvEntry()
                    traffic_entry.from_dict(row)
                    self.traffic_entries.append(traffic_entry)
                except ValueError:
                    self.config.logger.error("failed to parse %s in: %s",
                                             row, sys.exc_info()[1])
                except: # pylint: disable=W0702
                    self.config.logger.error("cataphoric error %s %s",
                                             row, sys.exc_info()[0])
        finally:
            pass

class TsharkCsvEntry(object):
    '''Represents a single log message of TShark information. Not all fields from the CSV
       file are retained as we're not interested in framing data'''

    def __init__(self):
        self.protocol = None
        self.src_address = None
        self.src_hostname = None
        self.src_port = None
        self.dst_address = None
        self.dst_hostname = None
        self.dst_port = None
        self.rx_bytes = None
        self.tx_bytes = None
        self.start_timestamp = None
        self.duration = None

    def from_dict(self, msg_dict):
        '''Does some pre-processing for the CSV for import'''

        # Forced lower here is to allow tshark data to directly map to port protocols
        self.protocol = ndr.PortProtocols(msg_dict['protocol'].lower())
        self.src_address = ipaddress.ip_address(msg_dict['src_addr'])
        self.src_hostname = msg_dict['src_hostname']
        self.src_port = int(msg_dict['src_port'])
        self.dst_address = ipaddress.ip_address(msg_dict['dst_addr'])
        self.dst_hostname = msg_dict['dst_hostname']
        self.dst_port = int(msg_dict['dst_port'])
        self.rx_bytes = int(msg_dict['rx_bytes'])
        self.tx_bytes = int(msg_dict['tx_bytes'])

        dt_obj = datetime.datetime.strptime(msg_dict['start_time'],
                                            "%Y-%m-%d %H:%M:%S")
        self.start_timestamp = dt_obj.timestamp()
        self.duration = float(msg_dict['duration'])

    def to_dict(self):
        '''Converts the entry to dict format for serialization'''
        traffic_entry = {}
        traffic_entry['protocol'] = self.protocol.value
        traffic_entry['src_addr'] = self.src_address.compressed
        traffic_entry['src_hostname'] = self.src_hostname
        traffic_entry['src_port'] = int(self.src_port)
        traffic_entry['dst_addr'] = self.dst_address.compressed
        traffic_entry['dst_hostname'] = self.dst_hostname
        traffic_entry['dst_port'] = int(self.dst_port)
        traffic_entry['rx_bytes'] = int(self.rx_bytes)
        traffic_entry['tx_bytes'] = int(self.tx_bytes)
        traffic_entry['start_timestamp'] = self.start_timestamp
        traffic_entry['duration'] = float(self.duration)
        return traffic_entry
