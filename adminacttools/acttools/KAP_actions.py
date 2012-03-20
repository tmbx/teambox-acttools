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
# KAP_actions.py --- Application of KAP data on a KPS system
# Copyright (C) 2006-2012 Opersys inc.

# Author: François-Denis Gonthier

# Application of a KAP doesn't automatically make a KPS functionnal.
# This class doesn't try to determine if a KPS will work after all the
# provided KAP elements are applied on the system.
#
# Doing so would require checking the whole system database and
# configuration file to determine what is missing, if anything.  This
# code is not the right place to do that.

import tempfile

from kctllib.kkeys import *
from kctllib.ktbxsosdconfig import *
from kctllib.ktbxsosdconfigdaemon import *
from kctllib.kdatabase import *

# kpython
from kfile import *
from krun import *

KAPActions = []

# Fatal error.  This means the activation failed.
class KAPActionException(Exception): pass

# Warning.  Might not mean a failed activation.  Might mean a partial
# KAP was sent.
class KAPActionWarning(Exception): pass

db_init()

__all__ = ["KAPActions", "KAPActionException", "KAPActionWarning"]

def openconfig():
    return KTbxsosdConfig(source_file = "/etc/teambox/tbxsosd/tbxsosd.conf",
                            user_file = "/etc/teambox/tbxsosd/web.conf")

def action_sig_skey(activator, kap):
    if kap.email_sig_skey:
        key = kap.email_sig_skey
        activator.keyset.set_sig_skey(key)
        sdb_importprivkey("sig", key.id, key.owner, key.key)
        db_commit()
    else:
        raise KAPActionWarning("No private signature key provided.")

def action_sig_pkey(activator, kap):
    if kap.email_sig_pkey:
        key = kap.email_sig_pkey
        activator.keyset.set_sig_pkey(key)
        sdb_importpubkey("sig", key.id, key.owner, key.key)
        db_commit()
    else:
        raise KAPActionWarning("No public signature key provided.")

def action_enc_skey(activator, kap):
    if kap.key_id:
        key_owner = "Unknown owner %d" % kap.key_id
        if kap.email_sig_pkey:
            key_owner = kap.email_sig_pkey.owner
        activator.keyset.set_keyid_and_owner(kap.key_id, key_owner)
        key = activator.keyset.enc_skey
        sdb_importprivkey("enc", key.id, key.owner, key.key)
        db_commit()
    else:
        raise KAPActionWarning("No key ID provided.")

def action_enc_pkey(activator, kap):
    if kap.key_id:
        key_owner = "Unknown owner %d" % kap.key_id
        if kap.email_sig_pkey:
            key_owner = kap.email_sig_pkey.owner
        activator.keyset.set_keyid_and_owner(kap.key_id, key_owner)
        key = activator.keyset.enc_pkey
        sdb_importpubkey("enc", key.id, key.owner, key.key)
        db_commit()
    else:
        raise KAPActionWarning("No key ID provided.")

def action_license(activator, kap):
    if kap.license:
        (_, tmp_path) = tempfile.mkstemp()
        write_file(tmp_path, kap.license)

        # FIXME: This is a copy of some code in kctlcmd.
        kctlbin = kparams_get("kctlbin")
        cmd = [kctlbin, "showlicensefile", tmp_path]
        proc = KPopen("", cmd)
        lines = re.split("\n", proc.stdout)

        try:
            # Get the first line.
            (v, kdn) = re.split(": ", lines[0])
            if v != "kdn":
                raise KAPActionException("Unable to guess which KDN to use to import the license")
            else:
                sdb_set_org_license(kdn, kap.license)
                db_commit()
        except KctlException, ex:
            raise KAPActionException("Unable to apply license: %s", ex.message)
        finally:
            os.unlink(tmp_path)
    else:
        raise KAPActionWarning("No license provided.")

def action_kdn(activator, kap):
    if kap.kdn:
        activator.identity.kdn = kap.kdn
        activator.identity.save()

        config = openconfig()
        cfg_kdn = config.get("server.kdn")
        if cfg_kdn and cfg_kdn.find(kap.kdn) >= 0:
            config.set("server.kdn", " ".join([cfg_kdn, kap.kdn]))
        else:
            config.set("server.kdn", kap.kdn)
        config.save(target_file = "/etc/teambox/tbxsosd/web.conf")
    else:
        raise KAPActionWarning("No KDN provided.")

def action_neworg(activator, kap):
    if kap.kdn:
        orgs = sdb_lsorg()[1]
        doAdd = True
        if orgs:
            for o in orgs:
                if o[1] == kap.kdn:
                    doAdd = False
                    org_id = o[0]
        # The database returns a long integer here but we can usually
        # treat the org_id as an integer.
        if doAdd:
            org_id = sdb_addorg(kap.kdn)
            sdb_set_org_status(org_id, 2)
            db_commit()

            activator.identity.org_id = int(org_id)
            activator.identity.save()
            activator.save()
        else:
            activator.identity.org_id = int(org_id)
            activator.identity.save()
            activator.save()
            raise KAPActionWarning("Organization %s already exists." % kap.kdn)
    else:
        raise KAPActionWarning("No KDN provided.")

def action_bundle(activator, kap):
    if kap.bundle:
        (_, tmp_file) = tempfile.mkstemp()
        try:
            write_file(tmp_file, kap.bundle)

            kcfgdaemon = TbxsosdConfigDaemon()
            if kcfgdaemon.present():
                kcfgdaemon.install_bundle(tmp_file)
            else:
                raise KAPActionException("No configuration daemon present.")
        finally:
            os.unlink(tmp_file)

def action_closing(activator, kap):
    activator.step = 7
    activator.save()

KAPActions += [("Private signature key", action_sig_skey),
               ("Public signature key", action_sig_pkey),
               ("Private encryption key", action_enc_skey),
               ("Public encryption key", action_enc_pkey),
               ("KDN", action_kdn),
               ("New organization", action_neworg),
               ("License", action_license),
               ("KPS bundle", action_bundle),
               ("End of activation", action_closing)]
