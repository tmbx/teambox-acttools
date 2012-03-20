#
# Copyright (C) 2010-2012 inc.
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
from kfile import *
from tempfile import *

# Make sure we test local classes first.
sys.path.insert(0, ".")

from acttools import ssl

class TestStuff(unittest.TestCase):
    def setUp(self):
        self.cert_data = """-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----"""
        self.key_data = """-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----"""
        self.req_data = """-----BEGIN CERTIFICATE REQUEST-----
-----END CERTIFICATE REQUEST-----"""

    def testCertData(self):
        c1 = ssl.Cert(cert_data = self.cert_data)
        self.assertTrue(not c1.as_cert() is None)
        self.assertEqual(self.cert_data, c1.as_data())
        self.assertTrue(os.path.exists(c1.as_path()))

    def testCertFile(self):
        write_file("/tmp/cert", self.cert_data)
        c1 = ssl.Cert(cert_file = "/tmp/cert")
        self.assertTrue(not c1.as_cert() is None)
        self.assertEqual(self.cert_data, c1.as_data())
        self.assertTrue(os.path.exists(c1.as_path()))
        self.assertEqual("/tmp/cert", c1.as_path())
        c1.save("/tmp/cert2")
        c2 = ssl.Cert(cert_file = "/tmp/cert2")
        self.assertEqual(c1.as_data(), c2.as_data())
        self.assertTrue(os.path.exists(c2.as_path()))
        os.unlink("/tmp/cert")
        os.unlink("/tmp/cert2")

    def testKeyData(self):
        k1 = ssl.Key(key_data = self.key_data)
        self.assertTrue(not k1.as_key() is None)
        self.assertEqual(self.key_data, k1.as_data())
        self.assertTrue(os.path.exists(k1.as_path()))

    def testKeyFile(self):
        write_file("/tmp/key1", self.key_data)
        k1 = ssl.Key(key_file = "/tmp/key1")
        self.assertTrue(not k1.as_key() is None)
        self.assertEqual(self.key_data, k1.as_data())
        self.assertTrue(os.path.exists(k1.as_path()))
        k1.save("/tmp/key2")
        k2 = ssl.Key(key_file = "/tmp/key2")
        self.assertEqual(k1.as_data(), k2.as_data())
        self.assertTrue(os.path.exists(k2.as_path()))
        os.unlink("/tmp/key1")
        os.unlink("/tmp/key2")

    def testCSRData(self):
        r1 = ssl.Req(req_data = self.req_data)
        self.assertTrue(not r1.as_req() is None)
        self.assertEqual(self.req_data, r1.as_data())
        self.assertTrue(os.path.exists(r1.as_path()))

    def testCSRFile(self):
        write_file("/tmp/req1", self.req_data)
        r1 = ssl.Req(req_file = "/tmp/req1")
        self.assertTrue(not r1.as_req() is None)
        self.assertEqual(self.req_data, r1.as_data())
        self.assertTrue(os.path.exists(r1.as_path()))
        r1.save("/tmp/req2")
        r2 = ssl.Req(req_file = "/tmp/req2")
        self.assertEqual(r1.as_data(), r2.as_data())
        self.assertTrue(os.path.exists(r2.as_path()))
        os.unlink("/tmp/req1")
        os.unlink("/tmp/req2")

if __name__ == "__main__":
    unittest.main()
