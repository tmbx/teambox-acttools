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
# KeySet.py --- Activation key set manager class.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os, fcntl, stat
from lock import ReadLock, WriteLock
from kctllib.kkeys import *
from acttools import *

# kpython
from kfile import *

class KeySet:
    """This class is used to manipulate the set of keys required
    during an activation.

    This class has no save method since it only manipulates file and
    has no internal state.

    Locking on this class is possibly flakey.  To make sure you don't
    fuck things up, don't save references to the following attributes:
    enc_pkey, enc_skey, enc_zero_pkey, enc_zero_skey, sig_pkey,
    sig_skey.
    """

    def exists(basedir, keys_name):
        d = os.path.join(basedir, "keys", keys_name)
        exists = os.path.exists(d)
        isdir = os.path.isdir(d)
        islink = os.path.islink(d)
        return exists and isdir and not islink
    exists = staticmethod(exists)

    def __init__(self, basedir, keys_name, 
                 zero_pkey_data = None, zero_skey_data = None,
                 zero_pkey_file = None, zero_skey_file = None):
        self.keys_name = keys_name
        self.enc_zero_pkey = None
        self.enc_zero_skey = None
        self.enc_pkey = None
        self.enc_skey = None
        self.sig_pkey = None
        self.sig_skey = None

        self.wanted_mode = os.stat(basedir)[stat.ST_MODE]
        nx = ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.wanted_mode_nx = self.wanted_mode & nx
        self.wanted_uid = os.stat(basedir)[stat.ST_UID]
        self.wanted_gid = os.stat(basedir)[stat.ST_GID]

        self.keys_dir = os.path.join(basedir, "keys", keys_name)
        self._enc_zero_pkey_file = os.path.join(self.keys_dir, "email.0.enc.pkey")
        self._enc_zero_skey_file = os.path.join(self.keys_dir, "email.0.enc.skey")
        self._enc_skey_file = os.path.join(self.keys_dir, "email.enc.skey")
        self._enc_pkey_file = os.path.join(self.keys_dir, "email.enc.pkey")
        self._sig_skey_file = os.path.join(self.keys_dir, "email.sig.skey")
        self._sig_pkey_file = os.path.join(self.keys_dir, "email.sig.pkey")
        self._lockpath = os.path.join(self.keys_dir, "lock")
        self._lock = None

        if not os.path.exists(os.path.dirname(self.keys_dir)):
            d = os.path.dirname(self.keys_dir)
            os.mkdir(d)
            os.chmod(d, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(d, self.wanted_uid, self.wanted_gid)

        if not os.path.exists(self.keys_dir):
            os.mkdir(self.keys_dir)
            os.chmod(self.keys_dir, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(self.keys_dir, self.wanted_uid, self.wanted_gid)

        try:
            self._lock = ReadLock(self._lock, self._lockpath)

            if zero_pkey_data:
                write_file(self._enc_zero_pkey_file, zero_pkey_data)
                
            if zero_skey_data:
                write_file(self._enc_zero_skey_file, zero_skey_data)

            if zero_pkey_file:
                if os.path.exists(zero_pkey_file):
                    shutil.copyfile(zero_pkey_file, self._enc_zero_pkey_file)

            if zero_skey_file:
                if os.path.exists(zero_skey_file):
                    shutil.copyfile(zero_skey_file, self._enc_zero_skey_file)

            do_exists = False
            for i in [self._enc_zero_pkey_file, self._enc_zero_skey_file]:
                if os.path.exists(i): do_exists = True; break

            if do_exists:
                if os.path.exists(self._enc_zero_pkey_file):
                    self.enc_zero_pkey = Key.fromFile(self._enc_zero_pkey_file)
                if os.path.exists(self._enc_zero_skey_file):
                    self.enc_zero_skey = Key.fromFile(self._enc_zero_skey_file)
                if os.path.exists(self._enc_skey_file):
                    self.enc_skey = Key.fromFile(self._enc_skey_file)
                if os.path.exists(self._enc_pkey_file):
                    self.enc_pkey = Key.fromFile(self._enc_pkey_file)
                if os.path.exists(self._sig_pkey_file):
                    self.sig_pkey = Key.fromFile(self._sig_pkey_file)
                if os.path.exists(self._sig_skey_file):
                    self.sig_skey = Key.fromFile(self._sig_skey_file)
            else:
                (pkey, skey) = Key.newPair(Key.ENC_PAIR, 0, "")
                pkey.save(self._enc_zero_pkey_file)
                self.enc_zero_pkey = Key.fromFile(self._enc_zero_pkey_file)
                skey.save(self._enc_zero_skey_file)
                self.enc_zero_skey = Key.fromFile(self._enc_zero_skey_file)
                for f in [self._enc_zero_pkey_file, self._enc_zero_skey_file]:
                    if os.stat(f)[stat.ST_UID] == os.getuid():
                        os.chmod(f, self.wanted_mode_nx)
                        if os.getuid() == 0:
                            os.chown(f, self.wanted_uid, self.wanted_gid)
        finally:
            if self._lock:
                self._lock.unlock()

    def __getattribute__(self, attr):
        if not attr in self.__dict__:
            return AttributeError((self, attr))
        else:
            # This is a rather lame attempt at locking.
            if not attr in ["enc_zero_pkey", "enc_zero_skey",
                            "enc_pkey", "enc_skey",
                            "sig_pkey", "sig_skey"]:
                try:
                    self._lock = ReadLock(self._lock, self._lockpath)
                    obj = self.__dict__[attr]
                finally:
                    if self._lock:
                        self._lock.unlock()
                return obj
            else:
                return self.__dict__[attr]

    def set_keyid_and_owner(self, newkeyid, newkeyowner):
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            self.enc_zero_pkey.save(self._enc_pkey_file)
            self.enc_zero_skey.save(self._enc_skey_file)

            self.enc_pkey = Key.fromFile(self._enc_pkey_file)
            self.enc_pkey.setkeyid(newkeyid)
            self.enc_pkey.setkeyname(newkeyowner)

            self.enc_skey = Key.fromFile(self._enc_skey_file)
            self.enc_skey.setkeyid(newkeyid)
            self.enc_skey.setkeyname(newkeyowner)

            for f in [self._enc_pkey_file, self._enc_skey_file]:
                # FIXME: Perhaps consider another mode for the secret
                # encryption key.
                if os.stat(f)[stat.ST_UID] == os.getuid():
                    os.chmod(f, self.wanted_mode_nx)
                    if os.getuid() == 0:
                        os.chown(f, self.wanted_uid, self.wanted_gid)
        finally:
            if self._lock:
                self._lock.unlock()

    def set_sig_skey(self, sig_skey):
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            sig_skey.save(self._sig_skey_file)
            self.sig_skey = Key.fromFile(self._sig_skey_file)
            # FIXME: Perhaps consider another mode for the secret
            # encryption key.
            if os.stat(self._sig_skey_file)[stat.ST_UID] == os.getuid():
                os.chmod(self._sig_skey_file, self.wanted_mode_nx)
                if os.getuid() == 0:
                    os.chown(self._sig_skey_file, self.wanted_uid, self.wanted_gid)
        finally:
            if self._lock:
                self._lock.unlock()

    def set_sig_pkey(self, sig_pkey):
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            sig_pkey.save(self._sig_pkey_file)
            self.sig_pkey = Key.fromFile(self._sig_pkey_file)
            if os.stat(self._sig_pkey_file)[stat.ST_UID] == os.getuid():
                os.chmod(self._sig_pkey_file, self.wanted_mode_nx)
                if os.getuid() == 0:
                    os.chown(self._sig_pkey_file, self.wanted_uid, self.wanted_gid)
        finally:
            if self._lock:
                self._lock.unlock()

    def delete(self):
        if os.path.exists(self.keys_dir):
            try:
                self._lock = WriteLock(self._lock, self._lockpath)
                for i in [self.sig_pkey, self.sig_skey, self.enc_pkey, self.enc_skey,
                          self.enc_zero_skey, self.enc_zero_pkey]:
                    if i: i.delete()
            finally:
                if self._lock:
                    self._lock.unlock()
            if os.path.exists(self.keys_dir):
                if os.path.isdir(self.keys_dir) and not os.path.islink(self.keys_dir):
                    os.rmdir(self.keys_dir)
                else:
                    s = "Key set directory %s is not a regular directory: not deleting." % self.keys_dir
                    raise ActivationException(s)
