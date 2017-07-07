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

"""Exceptions used through the NDR package"""

class NdrExpection(Exception):
    """Base class for all NDR exceptions"""
    pass

class NmapFailure(NdrExpection):
    """Raised when NMAP shits itself"""
    def __init__(self, error_code, stderr_output):
        self.error_code = error_code
        self.stderr_output = stderr_output
        NdrExpection.__init__(self)

class UploadFailure(NdrExpection):
    """Raised when NMAP shits itself"""
    def __init__(self, error_code, stderr_output):
        self.error_code = error_code
        self.stderr_output = stderr_output
        NdrExpection.__init__(self)
