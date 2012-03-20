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
# Activation.py --- Activation identity manager class.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os, yaml, subprocess, ssl, fcntl, tarfile, gzip, codecs, stat, StringIO, exceptions
from lock import ReadLock, WriteLock
from M2Crypto import X509, EVP, util, BIO, RSA
from Activation import ActivationException

# kpython
from kfile import *

class RubyString:
    def __init__(self, val):
        self.val = val
    def __str__(self):
        return self.val

def simple_decode(s_raw):
    return codecs.getdecoder("string_escape")(s_raw)[0]

def RubyString_representer(dumper, obj):
    if type(obj.val) is str:
        return dumper.represent_scalar("!string", codecs.getencoder("string_escape")(obj.val)[0])
    elif type(obj.val) is unicode:
        return dumper.represent_scalar("!string", codecs.getencoder("raw_unicode_escape")(obj.val)[0])

def RubyString_constructor(loader, node):
    return node.value

class Identity:
    def _check_cert(self):
        # Check if the CSR key match the certificate key.
        po = subprocess.Popen(["sslsigntool", "check_match", self._id_csr_path, self._id_cert_path],
                              stdin = None,
                              stdout = subprocess.PIPE,
                              stderr = subprocess.PIPE)
        po.communicate()
        po.wait()
        self.asserted = (po.returncode == 0)

    def _load_skey(self):
        if os.path.exists(self._id_skey_path):
            self._gen_rsa = RSA.load_key(self._id_skey_path)
        else:
            raise ActivationException("No secret key in %s." % self._id_skey_path)

    def _load_CSR(self):
        # Load the CSR if it exists.
        if os.path.exists(self._id_csr_path):
            csr = X509.load_request(self._id_csr_path)

            csr_subject = csr.get_subject()
            self.country = csr_subject.C
            self.state = csr_subject.ST
            self.location = csr_subject.L
            self.org = csr_subject.O
            self.org_unit = csr_subject.OU
            self.domain = csr_subject.CN
            self.email = csr_subject.emailAddress

            # Extract the public key and version from the CSR
            self._pkey = csr.get_pubkey()
        else:
            raise ActivationException("No identity CSR in %s." % self._id_csr_path)

    def _load_cert(self):
        if os.path.exists(self._id_cert_path):
            cert = X509.load_cert(self._id_cert_path)
            self._check_cert()

    def _load_Identity(self):
        # Load the identity data if it exists.
        if os.path.exists(self._id_data_path):
            yaml.add_constructor("!string", RubyString_constructor)
            s_uni = read_file(self._id_data_path)
            data = yaml.load(s_uni)

            if data.has_key(":kdn"):
                self.kdn = data[":kdn"]
            if data.has_key(":admin_name"):
                self.admin_name = data[":admin_name"]
            if data.has_key(":admin_email"):
                self.admin_email = data[":admin_email"]
            if data.has_key(":parent_id_name"):
                self.parent_id_name = data[":parent_id_name"]
            if data.has_key(":org_id"):
                if not data[":org_id"] is None:
                    self.org_id = data[":org_id"]
                else:
                    self.org_id = None
        else:
            raise ActivationException("No identity data file in %s." % self._id_data_path)

    def _save_Identity(self):
        # Make sure we have everything to generate the identity database.
        data = {}
        for k in ["admin_name", "admin_email"]:
            if hasattr(self, k) and getattr(self, k):
                # The : is to keep compatibility with Ruby stuff.
                data[":" + k] = RubyString(self.__dict__[k])
            else:
                v = (k, str(self.__dict__[k]))
                raise ActivationException("Invalid value for attribute %s: %s" % v)
        if self.kdn:
            data[":kdn"] = self.kdn
        if self.parent_id_name:
            data[":parent_id_name"] = self.parent_id_name
        if self.org_id:
            data[":org_id"] = self.org_id
        yaml.add_representer(RubyString, RubyString_representer)
        buf = StringIO.StringIO()
        yaml.dump(data, buf,
                  # I don't know if those options are required but
                  # adding them make PyYAML produce the exact same
                  # result as Ruby YAML library.
                  tags = False,
                  allow_unicode = False,
                  explicit_start = True,
                  default_flow_style = False)
        write_file(self._id_data_path, buf.getvalue())
        if os.stat(self._id_data_path)[stat.ST_UID] == os.getuid():
            os.chmod(self._id_data_path, self.wanted_mode_nx)
            if os.getuid() == 0:
                os.chown(self._id_data_path, self.wanted_uid, self.wanted_gid)

    def _save_skey(self):
        if self._gen_rsa:
            self._gen_rsa.save_key(self._id_skey_path, cipher = None)
            # FIXME: We might want to use another mode in this place.
            if os.stat(self._id_skey_path)[stat.ST_UID] == os.getuid():
                os.chmod(self._id_skey_path, self.wanted_mode_nx)
                if os.getuid() == 0:
                    os.chown(self._id_skey_path, self.wanted_uid, self.wanted_gid)

    def _save_CSR(self):
        def empty_callback(): pass

        # Make sure we have everything to generate the CSR.
        for k in ["country", "state", "location", "org", "domain"]:
            if not self.__dict__.has_key(k) or (not self.__dict__[k]):
                v = (k, str(self.__dict__[k]))
                raise ActivationException("Invalid value for attribute %s: %s" % v)

        csr = X509.Request()
        csr_subject = csr.get_subject()
        csr_subject.C = self.country
        csr_subject.ST = self.state
        csr_subject.L = self.location
        csr_subject.O = self.org
        if self.org_unit:
            csr_subject.OU = self.org_unit
        csr_subject.CN = self.domain
        if self.email:
            csr_subject.emailAddress = self.email

        if not self._pkey:
            self._gen_rsa = RSA.gen_key(512, 65537, empty_callback)
            self._pkey = EVP.PKey()

        # The keys shouldn't capture the RSA set here because this
        # would lead to both object destroying the RSA set.  It'll
        # be deleted with the rest of the instance of this class.
        self._pkey.assign_rsa(self._gen_rsa, capture = False)

        csr.set_pubkey(self._pkey)
        csr.sign(self._pkey, "md5")
        csr.save_pem(self._id_csr_path)
        if os.stat(self._id_csr_path)[stat.ST_UID] == os.getuid():
            os.chmod(self._id_csr_path, self.wanted_mode_nx)
            if os.getuid() == 0:
                os.chown(self._id_csr_path, self.wanted_uid, self.wanted_gid)

    def _import_data(self, data):
        def _import_data_extract(self, tf, fn, dest):
            try:
                ti = tf.getmember(fn)
                if ti.isreg():
                    f = t.extractfile(fn)
                    write_file(dest, f.read())
                    if os.stat(dest)[stat.ST_UID] == os.getuid():
                        os.chmod(dest, self.wanted_mode_nx)
                        if os.getuid() == 0:
                            os.chown(dest, self.wanted_uid, self.wanted_gid)
                else:
                    raise ActivationException("Invalid identity data.")
            except KeyError, ex:
                pass

        dec = codecs.getdecoder("base64_codec")
        s = StringIO.StringIO(dec(data)[0])
        t = tarfile.open(fileobj = s, mode = "r")
        _import_data_extract(self, t, "csr", self._id_csr_path)
        _import_data_extract(self, t, "key", self._id_skey_path)
        _import_data_extract(self, t, "cert", self._id_cert_path)
        _import_data_extract(self, t, "id_data", self._id_data_path)

    def exists(basedir, identity_name):
        d = os.path.join(basedir, "identity", identity_name)
        exists = os.path.exists(d)
        isdir = os.path.isdir(d)
        islink = os.path.islink(d)
        return exists and isdir and not islink
    exists = staticmethod(exists)

    def __init__(self, basedir, identity_name, import_data = None):
        # Data generated as part of the CSR.
        self._gen_rsa = None
        self._pkey = None

        # Identity data.
        self.id_name = None
        self.admin_name = None
        self.admin_email = None
        self.kdn = None
        self.org_id = None
        self.parent_id_name = None
        self.country = None
        self.state = None
        self.location = None
        self.org = None
        self.org_unit = None
        self.domain = None
        self.email = None
        self.asserted = False

        self.wanted_mode = os.stat(basedir)[stat.ST_MODE]
        nx = ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.wanted_mode_nx = self.wanted_mode & nx
        self.wanted_uid = os.stat(basedir)[stat.ST_UID]
        self.wanted_gid = os.stat(basedir)[stat.ST_GID]

        # Setup the identity file paths.
        self.identity_dir = os.path.join(basedir, "identity", identity_name)
        self._id_csr_path = os.path.join(self.identity_dir, "csr")
        self._id_csr_data_path = os.path.join(self.identity_dir, "csr_data")
        self._id_skey_path = os.path.join(self.identity_dir, "key")
        self._id_data_path = os.path.join(self.identity_dir, "id_data")
        self._id_cert_path = os.path.join(self.identity_dir, "cert")
        self._lockpath = os.path.join(self.identity_dir, "lock")
        self._lock = None

        # Make the parent 'identity' directory if it doesn't exists.
        if not os.path.exists(os.path.dirname(self.identity_dir)):
            d = os.path.dirname(self.identity_dir)
            os.mkdir(d)
            os.chmod(d, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(d, self.wanted_uid, self.wanted_gid)

        if not os.path.exists(self.identity_dir):
            os.mkdir(self.identity_dir)
            os.chmod(self.identity_dir, self.wanted_mode)
            if os.getuid() == 0:
                os.chown(self.identity_dir, self.wanted_uid, self.wanted_gid)
        elif not os.path.isdir(self.identity_dir) or os.path.islink(self.identity_dir):
            raise ActivationException("%s is not a directory." % self.identity_dir)

        self.id_name = os.path.basename(self.identity_dir)

        if import_data:
            try:
                self._lock = WriteLock(self._lock, self._lockpath)
                self._import_data(import_data)
            finally:
                if self._lock:
                    self._lock.unlock()

        # Load the identity if any of the related files exists.
        try:
            self._lock = ReadLock(self._lock, self._lockpath)

            do_exists = False
            for i in [self._id_csr_path, self._id_skey_path, self._id_data_path]:
                if os.path.exists(i): do_exists = True; break

            if do_exists:
                self._load_Identity()
                self._load_CSR()
                self._load_cert()
                self._load_skey()
        finally:
            if self._lock:
                self._lock.unlock()

    def get_CSR(self):
        try:
            self._lock = ReadLock(self._lock, self._lockpath)
            if os.path.exists(self._id_csr_path):
                return read_file(self._id_csr_path)
        finally:
            if self._lock:
                self._lock.unlock()

    def get_cert(self):
        try:
            self._lock = ReadLock(self._lock, self._lockpath)
            if os.path.exists(self._id_cert_path):
                return read_file(self._id_cert_path)
        finally:
            if self._lock:
                self._lock.unlock()

    def get_key(self):
        try:
            self._lock = ReadLock(self._lock, self._lockpath)
            if os.path.exists(self._id_skey_path):
                return read_file(self._id_skey_path)
        finally:
            if self._lock:
                self._lock.unlock()

    def set_cert(self, cert_str):
        if not os.path.exists(self._id_csr_path):
            raise ActivationException("No CSR generated for this identity.")
        else:
            try:
                self._lock = WriteLock(self._lock, self._lockpath)
                write_file(self._id_cert_path, cert_str)
                self._check_cert()
                if not self.asserted:
                    os.unlink(self._id_cert_path)
                    raise ActivationException("Invalid certificate.")
                else:
                    if os.stat(self._id_cert_path)[stat.ST_UID] == os.getuid():
                        os.chmod(self._id_cert_path, self.wanted_mode_nx)
                        if os.getuid() == 0:
                            os.chown(self._id_cert_path, self.wanted_uid, self.wanted_gid)
            finally:
                if self._lock:
                    self._lock.unlock()

    def save(self):
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            self._save_Identity()
            self._save_CSR()
            self._save_skey()
        finally:
            if self._lock:
                self._lock.unlock()

    def delete(self):
        try:
            self._lock = WriteLock(self._lock, self._lockpath)
            for p in [self._id_csr_path, self._id_cert_path, self._id_data_path,
                      self._id_skey_path, self._id_csr_data_path]:
                if os.path.exists(p):
                    os.unlink(p)
        finally:
            if self._lock:
                self._lock.unlock()
        os.rmdir(self.identity_dir)

    def export_data(self):
        """Create a base64-encoded tar.gz bundle of all the files
        related to activation."""
        enc = codecs.getencoder("base64_codec")
        s = StringIO.StringIO()
        g = gzip.GzipFile(fileobj = s, mode = "w")
        t = tarfile.open(fileobj = g, mode = "w")
        for fi in [self._id_csr_path, self._id_cert_path, self._id_data_path, self._id_skey_path]:
            if os.path.exists(fi):
                t.add(fi ,arcname = os.path.basename(fi))
        t.close()
        g.close()
        return enc(s.getvalue())[0]

    def __str__(self):
        s = []
        for k in self.__dict__.keys():
            s.append("%s: %s" % (k, str(self.__dict__[k])))
        return "[" + ", ".join(s) + "]"
