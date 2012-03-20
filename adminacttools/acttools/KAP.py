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
# KAP.py --- Cooking recipe for making KAP.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os, commands, tarfile, shutil, KAP_actions
from subprocess import *
from Workdir import *
from kctllib.kkeys import *

# kpython
from kfile import *

class KAPException(Exception): pass

class KAPData:
    def __init__(self):
        self.kap_type = None
        self.email_sig_pkey = None
        self.email_sig_skey = None
        self.email_enc_pkey = None
        self.key_id = None
        self.kdn = None
        self.bundle = None
        self.license = None

def show_KAP(kap_data):
    s = ""
    if kap_data.email_sig_pkey:
        s += "Public signature key: " + str(kap_data.email_sig_pkey) + "\n"
    if kap_data.email_sig_skey:
        s += "Private signature key: " + str(kap_data.email_sig_skey) + "\n"
    if kap_data.email_enc_pkey:
        s += "Public encryption key: " + str(kap_data.email_enc_pkey) + "\n"
    if kap_data.key_id:
        s += "Key ID: " + str(kap_data.key_id) + "\n"
    if kap_data.kdn:
        s += "KDN: " + str(kap_data.kdn) + "\n"
    if kap_data.bundle:
        s += "Bundle present.\n"
    if kap_data.license:
        s += "License present.\n"
    return s

def read_KAP(kap_file, teambox_email_pkey = None, encrypt_skey = None):
    workdir = Workdir()

    try:
        kap = KAPData()

        # Check if this is an encrypted file.
        is_true_KAP = False
        kap_header_check = None
        try:
            kap_header_check = open(kap_file, "r")
            kap_header = kap_header_check.read(39)
            if kap_header == "--- Encrypted chunk for KPS version 1.0":
                is_true_KAP = True
        finally:
            kap_header_check.close()

        # Decrypt the KAP.
        if is_true_KAP:
            decrypt = Popen(args = ["kpsinstalltool",
                                    "decrypt_verify",
                                    teambox_email_pkey,
                                    encrypt_skey,
                                    kap_file,
                                    os.path.join(workdir.path(), "kap.tar.gz")],
                            shell = False,
                            stdout = PIPE,
                            stderr = PIPE)
            (_, err_text) = decrypt.communicate()
            decrypt.wait()
            if decrypt.returncode != 0:
                raise KAPException("kpsinstalltool error: %s" % err_text)
        else:
            shutil.copyfile(kap_file, os.path.join(workdir.path(), "kap.tar.gz"))

        # Uncompress the KAP.
        if not os.path.exists(os.path.join(workdir.path(), "kap.tar.gz")):
            raise KAPException("Extracted KAP file does not exists.")
        t = tarfile.open(os.path.join(workdir.path(), "kap.tar.gz"))
        t.extractall(workdir.path())

        # Extract the KAP's content.
        fn = os.path.join(workdir.path(), "kap", "keys", "email.sig.pkey")
        if os.path.exists(fn):
            kap.email_sig_pkey = Key.fromBuffer(read_file(fn))
        fn = os.path.join(workdir.path(), "kap", "keys", "email.sig.skey")
        if os.path.exists(fn):
            kap.email_sig_skey = Key.fromBuffer(read_file(fn))
        fn = os.path.join(workdir.path(), "kap", "keys", "email.enc.pkey")
        if os.path.exists(fn):
            kap.email_enc_pkey = Key.fromBuffer(read_file(fn))
        fn = os.path.join(workdir.path(), "kap", "kps.bundle")
        if os.path.exists(fn):
            kap.bundle = read_file(fn)
        fn = os.path.join(workdir.path(), "kap", "kdn")
        if os.path.exists(fn):
            kap.kdn = read_file(fn).strip()
        fn = os.path.join(workdir.path(), "kap", "keyid")
        if os.path.exists(fn):
            kap.key_id = int(read_file(fn).strip())
        fn = os.path.join(workdir.path(), "kap", "lic")
        if os.path.exists(fn):
            kap.license = read_file(fn)

    finally:
        workdir.close()

    return kap

def write_KAP(kap, kap_file, do_encrypt = True, teambox_email_skey = None, encrypt_pkey = None):
    workdir = Workdir()
    workdir_sig = Workdir()

    if do_encrypt and (not teambox_email_skey or not encrypt_pkey):
        raise KAPException("Encryption demanded but no key used.")

    try:
        # Copy the generated key files in $workdir/kap
        os.mkdir(os.path.join(workdir.path(), "kap"))
        os.mkdir(os.path.join(workdir.path(), "kap", "keys"))

        # Build the KAP.
        if kap.email_sig_pkey:
            kap.email_sig_pkey.save(os.path.join(workdir.path(), "kap", "keys", "email.sig.pkey"))
        if kap.email_sig_skey:
            kap.email_sig_skey.save(os.path.join(workdir.path(), "kap", "keys", "email.sig.skey"))
        if kap.email_enc_pkey:
            kap.email_enc_pkey.save(os.path.join(workdir.path(), "kap", "keys", "email.enc.pkey"))
        if kap.bundle:
            bundle_path = os.path.join(workdir.path(), "kap", "kps.bundle")
            write_file(bundle_path, kap.bundle)
        if kap.kdn:
            kdn_path = os.path.join(workdir.path(), "kap", "kdn")
            write_file(kdn_path, kap.kdn)
        if kap.key_id:
            key_id_path = os.path.join(workdir.path(), "kap", "keyid")
            write_file(key_id_path, str(kap.key_id))
        if kap.license:
            license_file_path = os.path.join(workdir.path(), "kap", "lic")
            write_file(license_file_path, kap.license)

        workdir.tar(os.path.join(workdir_sig.path(), "kap.tar.gz"), compressed = True)

        # Encrypt the KAP.
        kap_zip = os.path.join(workdir_sig.path(), "kap.tar.gz")
        if do_encrypt:
            encrypt = Popen(args = ["kpsinstalltool",
                                    "sign_encrypt",
                                    teambox_email_skey,
                                    encrypt_pkey,
                                    kap_zip,
                                    kap_file],
                            shell = False,
                            stdout = PIPE,
                            stderr = PIPE)
            (_, err_text) = encrypt.communicate()
            encrypt.wait()
            if encrypt.returncode != 0:
                raise KAPException("kpsinstalltool error: %s" % err_text)
        else:
            shutil.copyfile(kap_zip, kap_file)

    finally:
        workdir_sig.close()
        workdir.close()
