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
# ssl.py --- SSL object wrappers.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os, tempfile
from M2Crypto import EVP, X509, RSA
from Activation import ActivationException

# kpython
from kfile import *

class Cert:
    def __init__(self, cert_data = None, cert_file = None):
        self._path = None
        self._data = None
        self._cert = None
        self._is_temp = False

        if cert_file and not os.path.exists(cert_file):
            raise ActivationException("Certificate file %s doesn't exists." % cert_file)

        if cert_data and cert_file:
            raise ActivationException("Cannot use file data and file path at the same time.")
        elif cert_file and not cert_data:
            self._path = cert_file
            self._data = read_file(self._path).strip()
            self._cert = X509.load_cert_string(self._data)
        elif cert_data and not cert_file:
            self._path = tempfile.mktemp()
            write_file(self._path, cert_data.strip())
            self._data = cert_data.strip()
            self._cert = X509.load_cert_string(self._data)
            self._is_temp = True

    def __del__(self):
        if self._is_temp:
            if os.path.exists(self._path):
                os.unlink(self._path)

    def as_data(self):
        return self._data

    def as_cert(self):
        return self._cert

    def as_path(self):
        return self._path

    def save(self, target_file = None):
        if target_file:
            f = target_file
        else:
            f = self._path
        self._data = self._cert.as_pem().strip()
        write_file(f, self._data)

class Key:
    def __init__(self, key_data = None, key_file = None):
        self._path = None
        self._data = None
        self._key = None
        self._is_temp = False

        if key_file and not os.path.exists(key_file):
            raise ActivationException("Key file %s doesn't exists." % key_file)

        if key_data and key_file:
            raise ActivationException("Cannot use file data and file path at the same time.")
        elif key_file and not key_data:
            self._path = key_file
            self._data = read_file(self._path).strip()
            self._key = EVP.PKey()
            self._key.assign_rsa(RSA.load_key_string(self._data))
        elif key_data and not key_file:
            self._path = tempfile.mktemp()
            write_file(self._path, key_data.strip())
            self._data = key_data.strip()
            self._key = EVP.PKey()
            self._key.assign_rsa(RSA.load_key_string(self._data))
            self._is_temp = True

    def __del__(self):
        if self._is_temp:
            if os.path.exists(self._path):
                os.unlink(self._path)

    def as_data(self):
        return self._data

    def as_key(self):
        return self._key

    def as_path(self):
        return self._path

    def save(self, target_file = None):
        if target_file:
            f = target_file
        else:
            f = self._path
        self._data = self._key.as_pem(cipher = None).strip()
        write_file(f, self._data)

class Req:
    def __init__(self, req_data = None, req_file = None):
        self._path = None
        self._data = None
        self._req = None
        self._is_temp = False

        if req_file and not os.path.exists(req_file):
            raise ActivationException("Certificate request file %s doesn't exists." % req_file)

        if req_data and req_file:
            raise ActivationException("Cannot use file data and file path at the same time.")
        elif req_file and not req_data:
            self._path = req_file
            self._req = X509.load_request(self._path)
            self._data = self._req.as_pem().strip()
        elif req_data and not req_file:
            self._path = tempfile.mktemp()
            write_file(self._path, req_data)
            self._req = X509.load_request(self._path)
            self._data = self._req.as_pem().strip()
            self._is_temp = True

    def __del__(self):
        if self._is_temp:
            if os.path.exists(self._path):
                os.unlink(self._path)

    def as_data(self):
        return self._data

    def as_req(self):
        return self._req

    def as_path(self):
        return self._path

    def save(self, target_file = None):
        if target_file:
            f = target_file
        else:
            f = self._path
        self._data = self._req.as_pem().strip()
        write_file(f, self._data)
