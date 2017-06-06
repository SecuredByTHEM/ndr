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

'''Defines handy utility functions across NDR'''

def set_dict_if_not_none(the_dict, key, value):
    '''Wrapper function for easing serialization pain'''
    if value is None:
        return

    the_dict[key] = value

def set_value_if_dict_exists(the_dict, key):
    '''Wrapper function for deserialization code'''
    if key not in the_dict:
        return

    return the_dict[key]

def return_value_if_key_exists(the_dict, key):
    '''Wrapper function for helping deserialization'''
    if key in the_dict:
        return the_dict[key]

    return None
