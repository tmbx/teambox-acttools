#
# Copyright (C) 2010-2012 Opersys inc.
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License, not any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import types
from config import AdminConfig
from config import ClientManager
from config import KeyConsistencyException
from kreadline import Command

command_classes = []
_command_module = __import__('cliadmcmds.cliadmcmds', fromlist = ['cliadmcmds'])

for nm in dir(_command_module):
    obj = getattr(_command_module, nm)
    if obj is Command: pass
    elif isinstance(obj, (type, types.ClassType)) and issubclass(obj, Command):
        command_classes.append(obj())
