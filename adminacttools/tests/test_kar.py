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
