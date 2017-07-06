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

from enum import Enum
from ndr import IngestMessage, IngestMessageTypes


class Syslog(object):
    def __init__(self):
        self.syslog_entries = []

    def __iter__(self):
        return iter(self.syslog_entries)

    def add_entry(self, syslog_msg):
        '''Loads a message into the syslog entry'''
        if isinstance(syslog_msg, SyslogEntry) is False:
            raise ValueError("SyslogUploadMessage only takes SyslogEntry!")
        self.syslog_entries.append(syslog_msg)

    def count(self):
        '''Returns the number of entries in a log'''
        return len(self.syslog_entries)

class SyslogUploadMessage(IngestMessage, Syslog):
    '''Uploads logs from syslog formatted in a JSON manner.

    This class depends on syslog-ng's output to be formatted in JSON-formatted with the following
    fields present
     - program
     - priority
     - pid
     - message
     - facility
     - date

    syslog-ng formats one JSON object per line, these must be deserialized on a line-by-line
    basis'''

    def __init__(self, config=None):
        IngestMessage.__init__(
            self, config, IngestMessageTypes.SYSLOG_UPLOAD)
        Syslog.__init__(self)

    def from_message(self, ingest_msg: IngestMessage):
        '''Converts an ingest message to a syslog message'''
        super().from_message(ingest_msg)

        # Now we need to deserialize the payload
        for log in self.headers['payload']:
            for log_entry in log['log']:
                self.syslog_entries.append(SyslogEntry.from_dict(log_entry))
        return self

    def create_report(self):
        syslog_dicts = []
        for log_entry in self.syslog_entries:
            syslog_dicts.append(log_entry.to_dict())

        self.add_header('payload', [{'log': syslog_dicts}])
        super().create_report()

class SyslogEntry():
    def __init__(self):
        self.timestamp = None
        self.program = None
        self.priority = None
        self.pid = None
        self.message = None
        self.facility = None
        self.host = None

    @classmethod
    def from_dict(cls, syslog_dict):
        '''Attempts to convert a YAML dict tree into a SyslogEntry.

        Because messages can be malformed or otherwise bad, this returns a KeyError
        if the values in the dict are missing. A special case is made for Message
        being empty. This represents a newline in the syslog, and we simply return
        None and discard it'''

        message = SyslogEntry()
        message.program = syslog_dict['program']
        message.priority = SyslogPriorities(syslog_dict['priority'])

        # PID will not always be present, set to none if its MIA
        if "pid" in syslog_dict:
            message.pid = int(syslog_dict["pid"])
        else:
            message.pid = None

        # Message can be blank, representing a newline. Toss it.
        if "message" not in syslog_dict:
            return None

        message.message = syslog_dict['message']
        message.timestamp = syslog_dict['timestamp']

        message.facility = SyslogFacilities(syslog_dict['facility'])
        message.host = syslog_dict['host']
        return message

    def to_dict(self):
        '''Returns a YAML structure of the entry as per the standardized YAML specification
           used by NDR'''

        syslog_dict = {}
        syslog_dict['program'] = self.program
        syslog_dict['priority'] = self.priority.value
        if self.pid:
            syslog_dict['pid'] = self.pid
        syslog_dict['message'] = self.message

        syslog_dict['timestamp'] = self.timestamp
        syslog_dict['facility'] = self.facility.value
        syslog_dict['host'] = self.host

        return syslog_dict

class SyslogFacilities(Enum):
    '''List of known facilities

    Officially, these are standardized by RFC 5425, however, in practice
    a lot of these have more common usages than what is defined by the RFC,
    so this is directly based on the names in syslog-ng; since we're feeding
    logs in based on what we get there we're going to use their names.
    '''

    KERN = "kern"
    USER = "user"
    MAIL = "mail"
    DAEMON = "daemon"
    AUTH = "auth"
    SYSLOG = "syslog"
    LPR = "lpr"
    NEWS = "news"
    UUCP = "uucp"
    CRON = "cron"
    AUTHPRV = "authpriv"
    FTP = "ftp"
    NTP = "ntp"
    SECURITY = "security"
    CONSOLE = "console"
    SOLARIS_CRON = "solaris-cron" # As defined in syslog-ng
    LOCAL0 = "local0"
    LOCAL1 = "local1"
    LOCAL2 = "local2"
    LOCAL3 = "local3"
    LOCAL4 = "local4"
    LOCAL5 = "local5"
    LOCAL6 = "local6"
    LOCAL7 = "local7"

class SyslogPriorities(Enum):
    '''List of known message types'''
    EMERGENCY = "emerg"
    ALERT = "alert"
    CRITICAL = "crit"
    ERROR = "err"
    WARNING = "warning"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"
