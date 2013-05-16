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
import unittest, sys, os
from stat import *

# Make sure we test local classes first.
sys.path.insert(0, ".")

from acttools.KAR import *
from acttools import ssl

class KARTest(unittest.TestCase):
    def test01KAPWrite(self):
        kar = read_KAR(kar_file = "tests/dummy_kar.bin",
                       teambox_ssl_cert = ssl.Cert(cert_file = "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_cert.pem"),
                       teambox_ssl_key = ssl.Key(key_file = "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_privkey_nopwd.pem"))

        self.assertEqual("KPS", kar.product_name)
        self.assertEqual("1.3", kar.product_version)
        self.assert_(len(kar.admin) > 0)
        self.assert_(not kar.parent_kdn)
        self.assert_(not kar.cert is None)
        self.assertEqual("ca", kar.cert.as_cert().get_subject().C)
        self.assertEqual("quebec", kar.cert.as_cert().get_subject().ST)
        self.assertEqual("Opersys inc.", kar.cert.as_cert().get_subject().O)
        self.assert_(not kar.cert.as_cert().get_subject().OU)
        self.assertEqual("Teambox KOS root CA", kar.cert.as_cert().get_subject().CN)
        self.assertEqual("support@teambox.co", kar.cert.as_cert().get_subject().emailAddress)
        self.assert_(len(kar.info) > 0)
        self.assert_(not kar.enc_pkey is None)

        write_KAR(kar, kar_file = "/tmp/kar2.bin",
                  teambox_ssl_cert = ssl.Cert(cert_file = "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_cert.pem"),
                  client_ssl_cert = ssl.Cert(cert_file = "/home/fdgonthier/repos/tbxsosd/kos_cert.pem"),
                  client_ssl_key = ssl.Key(key_file = "/home/fdgonthier/repos/tbxsosd/kos_skey.pem"))

    def test02KAPReread(self):
        kar = read_KAR(kar_file = "/tmp/kar2.bin",
                       teambox_ssl_cert = ssl.Cert(cert_file = "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_cert.pem"),
                       teambox_ssl_key = ssl.Key(key_file = "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_privkey_nopwd.pem"))
        self.assertEqual("KPS", kar.product_name)
        self.assertEqual("1.3", kar.product_version)
        self.assert_(len(kar.admin) > 0)
        self.assert_(not kar.parent_kdn)
        self.assert_(not kar.cert is None)
        self.assertEqual("ca", kar.cert.as_cert().get_subject().C)
        self.assertEqual("quebec", kar.cert.as_cert().get_subject().ST)
        self.assertEqual("Opersys inc.", kar.cert.as_cert().get_subject().O)
        self.assert_(not kar.cert.as_cert().get_subject().OU)
        self.assertEqual("Teambox KOS root CA", kar.cert.as_cert().get_subject().CN)
        self.assertEqual("support@teambox.co", kar.cert.as_cert().get_subject().emailAddress)
        self.assert_(len(kar.info) > 0)
        self.assert_(not kar.enc_pkey is None)
        os.unlink("/tmp/kar2.bin")
        
if __name__ == "__main__":
    unittest.main()
