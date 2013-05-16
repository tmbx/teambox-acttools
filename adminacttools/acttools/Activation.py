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

# -*- encoding: utf-8 -*-
# Activation.py --- Objects to be used for KPS activation.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os

class ActivationException(Exception):
    pass

class ActivationLockException(Exception):
    pass

teambox_email_pkey_path = "/usr/share/teambox-acttools/teambox_kps_email.sig.pkey"
teambox_kps_install_cert_path = "/usr/share/teambox-acttools/teambox_kps_install_cert.pem"

from Identity import Identity
from KeySet import KeySet
from Activator import Activator

def list_identity(base_dir):
    """Return the set of identities stored in base_dir."""
    id_path = os.path.join(base_dir, "identity")
    if os.path.exists(id_path):
        identities = os.listdir(id_path)
        return [Identity(base_dir, ident) for ident in identities]
    else:
        return []

def list_keys(base_dir):
    """Return the set of key sets stored in base_dir."""
    keys_path = os.path.join(base_dir, "keys")
    if os.path.exists(keys_path):
        keys = os.listdir(keys_path)
        return [KeySet(base_dir, keydir) for keydir in keys]
    else:
        return []

def list_activators(base_dir):
    """Return the set of activator objects stored in base_dir."""
    act_path = os.path.join(base_dir, "activation")
    if os.path.exists(act_path):
        acts = os.listdir(act_path)
        return [Activator(base_dir, actdir) for actdir in acts]
    else:
        return []
