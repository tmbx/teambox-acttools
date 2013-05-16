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
# KAR.py --- Cooking recipe for making KAR.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os, commands, gzip, re, shutil, stat, hashlib, ssl
from Workdir import *
from subprocess import *
from stat import *
from tarfile import *
from M2Crypto import m2, BIO, SMIME, X509
from kctllib.kkeys import *

# kpython
from kfile import *

class KARException(Exception):
    pass

class KARData:
    def __init__(self):
        self.parent_kdn = None
        self.product_name = None
        self.product_version = None
        self.admin = None
        self.info = None
        self.enc_pkey = None
        self.cert = None

def tar_getfirstmember(tar, flist):
    for f in flist:
        try:
            return tar.getmember(f)
        except KeyError:
            pass
    return None

def read_KAR(teambox_ssl_key, teambox_ssl_cert, kar_file):
    workdir = Workdir()

    try:
        # Decrypt the file.
        s = SMIME.SMIME()
        s.set_cipher(SMIME.Cipher('aes_256_cbc'))
        s.load_key(teambox_ssl_key.as_path(), teambox_ssl_cert.as_path())
        pkcs7 = SMIME.load_pkcs7(kar_file)
        data = s.decrypt(pkcs7)
        data = write_file(os.path.join(workdir.path(), "signed_kar.tar"), data)

        kar_tar_file = tarfile.TarFile(os.path.join(workdir.path(), "signed_kar.tar"), "r")

        # Verify the sanity of KAR level 2 file members.
        m_tar = tar_getfirstmember(kar_tar_file, ["kar.tar.gz", "./kar.tar.gz"])
        if not m_tar: raise KARException("KAR is missing 'kar.tar.gz'.")
        if not m_tar.isfile() and not m_tar.isdir():
            raise KARException("%s is not a regular file or a directory." % (m.name))
        m_sig = tar_getfirstmember(kar_tar_file, ["kar_sig", "./kar_sig"])
        if not m_sig: raise KARException("KAR is missing 'kar_sig'.")
        if not m_sig.isfile() and not m_sig.isdir():
            raise KARException("%s is not a regular file or a directory." % (m.name))

        # Extract the KAR level 2 file members.
        tar_list = kar_tar_file.getmembers()
        for i in tar_list:
            if not i.isfile() and not i.isdir():
                raise KARException("%s is not a regular file or directory." % (m.name))
            kar_tar_file.extract(i, workdir.path())

        # Calculate the hash of the data file to validate the KAR
        # signature.
        kar_hasher = hashlib.sha256()
        kar_hasher.update(kar_tar_file.extractfile(m_tar).read())
        write_file(os.path.join(workdir.path(), "kar_hash"), kar_hasher.hexdigest() + "\n")

        # Extract the KAR data file.
        tf = tarfile.TarFile(mode = "r", fileobj = gzip.GzipFile(os.path.join(workdir.path(), "kar.tar.gz"), "r"))
        tf.extractall(path = os.path.join(workdir.path()))

        # Verify the KAR signature.
        signverify = Popen(args = ["sslsigntool", "verify", "kar/cert.pem", "kar_hash", "kar_sig"],
                           stdout = PIPE,
                           stderr = PIPE,
                           cwd = workdir.path())
        (out_text, err_text) = signverify.communicate()
        if signverify.returncode != 0:
            raise KARException("sslsigntool exception: %s" % err_text.strip());

        # Extract some informations from the signing certificate.
        kar = KARData()
        fn = os.path.join(workdir.path(), "kar", "cert.pem")
        if os.path.exists(fn):
            kar.cert = ssl.Cert(cert_data = read_file(fn))

        # Read level 1 KAR data
        fn = os.path.join(workdir.path(), "kar", "product_name")
        if os.path.exists(fn):
            kar.product_name = read_file(fn).strip()
        fn = os.path.join(workdir.path(), "kar", "product_version")
        if os.path.exists(fn):
            kar.product_version = read_file(fn).strip()
        fn = os.path.join(workdir.path(), "kar", "info")
        if os.path.exists(fn):
            kar.info = read_file(fn)
        fn = os.path.join(workdir.path(), "kar", "parent_kdn")
        if os.path.exists(fn):
            kar.parent_kdn = read_file(fn).strip()
        fn = os.path.join(workdir.path(), "kar", "admin")
        if os.path.exists(fn):
            kar.admin = read_file(fn).strip()
        fn = os.path.join(workdir.path(), "kar", "kar.enc.pkey")
        if os.path.exists(fn):
            kar.enc_pkey = Key.fromFile(fn)
        fn = os.path.join(workdir.path(), "kar", "info")
        if os.path.exists(fn):
            kar.info = read_file(fn)

    finally:
        # Remove the temporaries
        workdir.close()

    # Return the KAR data.
    return kar

def write_KAR(kar, kar_file, teambox_ssl_cert, client_ssl_cert, client_ssl_key):
    workdir = Workdir()
    workdir_sig = Workdir()

    try:
        # Make sure we have everything that is mandatory in the KAR.
        for i in ['cert', 'enc_pkey', 'product_name', 'product_version', 'info', 'admin']:
            if not kar.__dict__.has_key(i):
                raise KARException("Value for %s field missing from KAR." % i)

        # Add the level 1 KAR data.
        os.mkdir(os.path.join(workdir.path(), "kar"))
        fn = os.path.join(workdir.path(), "kar", "cert.pem")
        kar.cert.save(fn)
        fn = os.path.join(workdir.path(), "kar", "kar.enc.pkey")
        kar.enc_pkey.save(fn)
        fn = os.path.join(workdir.path(), "kar", "product_name")
        write_file(fn, kar.product_name)
        fn = os.path.join(workdir.path(), "kar", "product_version")
        write_file(fn, kar.product_version)
        fn = os.path.join(workdir.path(), "kar", "info")
        write_file(fn, kar.info)
        fn = os.path.join(workdir.path(), "kar", "admin")
        write_file(fn, kar.admin)
        if kar.parent_kdn:
            fn = os.path.join(workdir.path(), "kar", "parent_kdn")
            write_file(fn, kar.parent_kdn)

        # Zip the level 1 KAR.
        workdir.tar(os.path.join(workdir.path(), "kar.tar.gz"), compressed = True)

        # Create the KAR file level 2 files.
        shutil.copy(os.path.join(workdir.path(), "kar.tar.gz"), workdir_sig.path())

        # Sign the KAR level 2.
        kar_hasher = hashlib.sha256()
        kar_hasher.update(read_file(os.path.join(workdir_sig.path(), "kar.tar.gz")))
        hash_path = os.path.join(workdir_sig.path(), "kar_hash")
        sig_path = os.path.join(workdir_sig.path(), "kar_sig")
        write_file(hash_path, kar_hasher.hexdigest() + "\n")
        sslsign = Popen(args = ["sslsigntool",
                                "sign",
                                client_ssl_cert.as_path(),
                                client_ssl_key.as_path(),
                                hash_path,
                                sig_path],
                        stdout = PIPE,
                        stderr = PIPE,
                        cwd = workdir_sig.path())
        (out_text, err_text) = sslsign.communicate()
        if sslsign.returncode != 0:
            raise KARException("sslsigntool exception: %s" % err_text.strip())
        os.unlink(hash_path)
        workdir_sig.tar(os.path.join(workdir_sig.path(), "signed_kar.tar"))

        # Encrypt the KAR level 2.
        inf = BIO.openfile(os.path.join(workdir_sig.path(), "signed_kar.tar"), "r")
        outf = BIO.openfile(kar_file, "w")

        xs = X509.X509_Stack()
        xs.push(teambox_ssl_cert.as_cert())

        s = SMIME.SMIME()
        s.set_cipher(SMIME.Cipher('aes_256_cbc'))
        s.set_x509_stack(xs)
        s.load_key(client_ssl_key.as_path(), certfile = teambox_ssl_cert.as_path())
        pkcs7 = s.encrypt(inf, flags = SMIME.PKCS7_BINARY)
        pkcs7.write(outf)
    finally:
        # Remove the temporaries.
        workdir.close()
        workdir_sig.close()
