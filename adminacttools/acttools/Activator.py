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
# Activator.py --- Activator object to manage activation data.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os, yaml, tempfile, KAR, KAP, ssl, fcntl, stat, datetime
from lock import ReadLock, WriteLock
from Activation import ActivationException, teambox_kps_install_cert_path, teambox_email_pkey_path
from KAP_actions import *
from kctllib.kkeys import *
from KeySet import KeySet
from Identity import Identity

# kpython
from kfile import *

class Activator:
    """This is the activator object.  An activator bridges together
    key sets and identites to produce KAR and process KAPs.

    It tries to stay mostly compatible with the Ruby version in the
    web interface.

    Keep in mind that .save() is never done implicitely by this
    object.

    The step instance variable is never set implicitely by this object
    since this object is not a wizard.  Callers should take care of
    modifying the step variable as they see fit.
    """

    def exists(basedir, act_name):
        d = os.path.join(basedir, "activation", act_name)
        exists = os.path.exists(d)
        isdir = os.path.isdir(d)
        islink = os.path.islink(d)
        return exists and isdir and not islink
    exists = staticmethod(exists)

    def _load_act(self):
        data = yaml.load(file(self._act_data_path, "r"))

        if data.has_key(":name"):
            self.name = data[":name"]
        if data.has_key(":step"):
            self.step = data[":step"]

        if data.has_key(":parent_id_name") and not data[":parent_id_name"] is None:
            if Identity.exists(self.basedir, data[":parent_id_name"]):
                self.parent_identity = Identity(self.basedir, data[":parent_id_name"])

        if data.has_key(":parent_keys_name") and not data[":parent_keys_name"] is None:
            if KeySet.exists(self.basedir, data[":parent_keys_name"]):
                self.parent_keyset = KeySet(self.basedir, data[":parent_keys_name"])

        if data.has_key(":id_name") and not data[":id_name"] is None:
            if Identity.exists(self.basedir, data[":id_name"]):
                self.identity = Identity(self.basedir, data[":id_name"])

        if data.has_key(":keys_name") and not data[":keys_name"] is None:
            if KeySet.exists(self.basedir, data[":keys_name"]):
                self.keyset = KeySet(self.basedir, data[":keys_name"])

    def _save_act(self):
        """Save the activator internal data to the disk."""
        data = {":name": self.name,
                ":step": self.step}

        if self.parent_identity:
            data[":parent_id_name"] = self.parent_identity.id_name
        if self.identity:
            data[":id_name"] = self.identity.id_name
        if self.parent_keyset:
            data[":parent_keys_name"] = self.parent_keyset.keys_name
        if self.keyset:
            data[":keys_name"] = self.keyset.keys_name

        if self.identity and self.identity.org_id:
            data[":org_id"] = self.identity.org_id

        yaml.dump(data, file(self._act_data_path, "w"),
                  # See Identity.py for comment relevant to those options.
                  tags = False,
                  allow_unicode = True,
                  explicit_start = True,
                  default_flow_style = False)
        if os.stat(self._act_data_path)[stat.ST_UID] == os.getuid():
            os.chmod(self._act_data_path, self.wanted_mode_nx)
            if os.getuid() == 0:
                os.chown(self._act_data_path, self.wanted_uid, self.wanted_gid)

    def is_activated(self):
        """Return true of the activator can be considered done."""
        # FIXME: We really ought to get a better condition than this.
        return (self.identity and not self.identity.kdn is None and not self.identity.org_id is None)

    def delete(self):
        """Delete this activator's data, along with KAR and KAPs it
        has saved."""
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            if os.path.exists(self._act_data_path):
                os.unlink(self._act_data_path)

            # Delete KAPs
            if os.path.exists(self._kap_dir):
                kaps = os.listdir(self._kap_dir)
                for k in kaps:
                    os.unlink(os.path.join(self._kap_dir, k))

            # Delete the KAR
            kar = os.path.join(self._kar_dir, "kar.bin")
            if os.path.exists(kar):
                os.unlink(kar)
        finally:
            if self._lock:
                self._lock.unlock()

        # Delete the activator directory.
        os.rmdir(self._act_dir)

    def save(self):
        """Save the activator data file."""
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            self._save_act()
        finally:
            if self._lock:
                self._lock.unlock()

    def get_KAR(self, product_name, product_version):
        def safe_none(s):
            if not s: return ""
            else: return s

        if not self.identity:
            raise ActivationException("No identity set.")
        if not self.keyset:
            raise ActivationException("No key set.")

        sign_id = self.identity
        if self.parent_identity:
            sign_id = self.parent_identity

        if not sign_id.asserted:
            s = "Identity %s is not asserted and thus cannot sign a KAR." % sign_id.id_name
            raise ActivationException(s)

        if not os.path.exists(os.path.dirname(self._kar_dir)):
            d = os.path.dirname(self._kar_dir)
            os.mkdir(d)
            os.chmod(d, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(d, self.wanted_uid, self.wanted_gid)
        if not os.path.exists(self._kar_dir):
            os.mkdir(self._kar_dir)
            os.chmod(self._kar_dir, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(self._kar_dir, self.wanted_uid, self.wanted_gid)

        kar = KAR.KARData()
        if self.parent_identity:
            kar.parent_kdn = self.parent_identity.kdn
        kar.product_name = product_name
        kar.product_version = product_version
        kar.admin = "%s <%s>" % (self.identity.admin_name, self.identity.admin_email)
        kar.enc_pkey = self.keyset.enc_zero_pkey

        # FIXME: We should probably transmit something other than a
        # plain text file but that works just fine for now.
        kar.info = "".join(["This is an activation done on the behalf of this organization:\n",
                            "Country: ", safe_none(self.identity.country), "\n",
                            "State: ", safe_none(self.identity.state), "\n",
                            "Loc: ", safe_none(self.identity.location), "\n",
                            "Org: ", safe_none(self.identity.org), "\n",
                            "Org Unit: ", safe_none(self.identity.org_unit), "\n",
                            "Domain: ", safe_none(self.identity.domain), "\n",
                            "Email: ", safe_none(self.identity.email), "\n"])
        kar.cert = ssl.Cert(cert_data = sign_id.get_cert())
        kar_file = os.path.join(self._kar_dir, "kar.bin")

        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            KAR.write_KAR(kar,
                          kar_file = kar_file,
                          teambox_ssl_cert = ssl.Cert(cert_file = teambox_kps_install_cert_path),
                          client_ssl_cert = ssl.Cert(cert_data = sign_id.get_cert()),
                          client_ssl_key = ssl.Key(key_data = sign_id.get_key()))

            if os.stat(kar_file)[stat.ST_UID] == os.getuid():
                os.chmod(kar_file, self.wanted_mode_nx)
                if os.getuid() == 0:
                    os.chown(kar_file, self.wanted_uid, self.wanted_gid)

            if not os.path.exists(kar_file):
                raise ActivationException("Cannot find the KAR file.")
            else:
                return read_file(kar_file)
        finally:
            if self._lock:
                self._lock.unlock()

    def apply_KAP(self, kap_name, do_apply, user_start_cb = None, user_end_cb = None):
        """Call KAP actions for a KAP registered to this activator."""

        def default_start_cb(name):
            sys.stdout.write("Applying %s: " % name)
            sys.stdout.flush()
        def default_end_cb(name, msg = None, is_warning = False, is_error = False):
            if not is_warning and not is_error:
                sys.stdout.write("ok\n")
            elif is_warning:
                sys.stdout.write(msg + "\n")
            elif is_error:
                sys.stdout.write("FATAL! %s\n" % msg)

        if user_start_cb:
            start_cb = user_start_cb
        else:
            start_cb = default_start_cb
        if user_end_cb:
            end_cb = user_end_cb
        else:
            end_cb = default_end_cb

        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            kap_file = os.path.join(self._kap_dir, kap_name)
            if not os.path.exists(kap_file):
                raise ActivationException("KAP %s doesn't exists." % kap_name)

            kap = KAP.read_KAP(kap_file,
                               teambox_email_pkey = teambox_email_pkey_path,
                               encrypt_skey = self.keyset.enc_zero_skey.key_path)
            for h in KAPActions:
                (action_text, action) = h
                try:
                    start_cb(action_text)
                    if do_apply:
                        action(self, kap)
                except KAPActionWarning, ex:
                    end_cb(action_text, str(ex), is_warning = True)
                except KAPActionException, ex:
                    end_cb(action_text, str(ex), is_error = True)
                else:
                    end_cb(action_text)
        finally:
            if self._lock:
                self._lock.unlock()

    def add_KAP(self, kap_data):
        """Register a KAP in the activator."""
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            if not os.path.exists(self._kap_dir):
                os.mkdir(self._kap_dir)
                os.chmod(self._kap_dir, self.wanted_mode)
                if os.getuid() == 0:
                    os.chown(self._kap_dir, self.wanted_uid, self.wanted_gid)
            cnt = 0
            while True:
                ad = os.path.join(self._kap_dir, "kap_%04d.bin" % cnt)
                cnt += 1
                if not os.path.exists(ad): break
            write_file(ad, kap_data)
            os.chmod(ad, self.wanted_mode_nx)
            if os.getuid() == 0:
                os.chown(ad, self.wanted_uid, self.wanted_gid)
            try:
                KAP.read_KAP(ad,
                             teambox_email_pkey = teambox_email_pkey_path,
                             encrypt_skey = self.keyset.enc_zero_skey.key_path)
            except KAP.KAPException, ex:
                # Erase the KAP if it's invalid.
                os.unlink(ad)
                raise
            return os.path.basename(ad)
        finally:
            if self._lock:
                self._lock.unlock()

    def del_KAP(self, kap_name):
        """Remove a KAP registered in the activator."""
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            kap_file = os.path.join(self._kap_dir, kap_name)
            if os.path.exists(kap_file):
                os.unlink(kap_file)
        finally:
            if self._lock:
                self._lock.unlock()

    def has_KAP(self, kap_name):
        """Return True if the activator has the KAP of that name registered."""
        it_has = False
        try:
            self._lock = ReadLock(self._lock, self._lockpath)
            if os.path.exists(self._kap_dir):
                it_has = os.path.exists(os.path.join(self._kap_dir, kap_name))
            else:
                it_has = False
        finally:
            if self._lock:
                self._lock.unlock()
        return it_has

    def list_KAP(self):
        """List the KAP objects registered to this activator."""
        if os.path.exists(self._kap_dir):
            try:
                self._lock = ReadLock(self._lock, self._lockpath)
                kaps = os.listdir(self._kap_dir)
            finally:
                if self._lock:
                    self._lock.unlock()
            return [(k,
                     KAP.read_KAP(os.path.join(self._kap_dir, k),
                                  teambox_email_pkey = teambox_email_pkey_path,
                                  encrypt_skey = self.keyset.enc_zero_skey.key_path),
                     datetime.datetime.fromtimestamp(os.stat(os.path.join(self._kap_dir, k))[stat.ST_MTIME])
                     )
                    for k in kaps]
        else:
            return []

    def __init__(self, basedir, act_name):
        self.basedir = basedir
        self.name = act_name
        self.step = None

        self.identity = None
        self.parent_identity = None
        self.keyset = None
        self.parent_keyset = None

        self.wanted_mode = os.stat(basedir)[stat.ST_MODE]
        nx = ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.wanted_mode_nx = self.wanted_mode & nx
        self.wanted_uid = os.stat(basedir)[stat.ST_UID]
        self.wanted_gid = os.stat(basedir)[stat.ST_GID]

        self._act_dir = os.path.join(basedir, "activation", self.name)
        self._kar_dir = os.path.join(basedir, "kar", self.name)
        self._kap_dir = os.path.join(basedir, "kar", self.name, "kap")
        self._act_data_path = os.path.join(self._act_dir, "act_data")
        self._lockpath = os.path.join(self._act_dir, "lock")
        self._lock = None

        if not os.path.exists(os.path.dirname(self._act_dir)):
            d = os.path.dirname(self._act_dir)
            os.mkdir(d)
            os.chmod(d, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(d, self.wanted_uid, self.wanted_gid)

        if not os.path.exists(self._act_dir):
            os.mkdir(self._act_dir)
            os.chmod(self._act_dir, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(self._act_dir, self.wanted_uid, self.wanted_gid)

        try:
            self._lock = ReadLock(self._lock, self._lockpath)
            if os.path.exists(self._act_data_path):
                self._load_act()
        finally:
            if self._lock:
                self._lock.unlock()
