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
