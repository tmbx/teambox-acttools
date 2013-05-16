#
# Copyright (C) 2010-2012 Opersys inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
