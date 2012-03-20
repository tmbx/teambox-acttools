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
import sys, unittest, os
from kfile import *
from kctllib.kparams import *

# Make sure we test local classes first.
sys.path.insert(0, ".")

from acttools.Identity import *

class TestIdentity(unittest.TestCase):
    def setUp(self):      
        self.a = Identity(basedir = "/tmp/teambox/", identity_name = "test_new")
        self.a.country = "CA"
        self.a.state = "Québec"
        self.a.location = "Sherbrooke"
        self.a.org = "Opersys"
        self.a.org_unit = None
        self.a.domain = "teambox.co"
        self.a.email = ""
        self.a.admin_name = "François-Denis Gonthier"
        self.a.admin_email = ""
        self.a.save()
        
    def tearDown(self):
        self.a.delete()

    def testNewIdentity(self):
        self.assertTrue(os.path.exists("/tmp/teambox/identity/test_new/key"))
        self.assertTrue(os.path.exists("/tmp/teambox/identity/test_new/id_data"))
        self.assertTrue(os.path.exists("/tmp/teambox/identity/test_new/csr"))

    def testLoadIdentity(self):
        self.assertEqual("CA", self.a.country)
        self.assertEqual("Québec", self.a.state)
        self.assertEqual("Sherbrooke", self.a.location)
        self.assertEqual("Opersys", self.a.org)
        self.assertEqual(None, self.a.org_unit)
        self.assertEqual("teambox.co", self.a.domain)
        self.assertEqual("François-Denis Gonthier", self.a.admin_name)
        self.assertEqual("", self.a.admin_email)

    def testSetCert(self):
        write_file("/tmp/csr", self.a.get_CSR())
        os.system(" ".join(["openssl", "x509", "-req",
                            "-in", "/tmp/csr",
                            "-CA", "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_cert.pem",
                            "-CAkey", "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_privkey_nopwd.pem",
                            "-set_serial", "0",
                            "-out", "/tmp/cert"]))
        self.a.set_cert(read_file("/tmp/cert"))
        self.assertTrue(self.a.asserted)
        idB = Identity("/tmp/teambox", "test_import", import_data = self.a.export_data())
        self.assertEqual(self.a.country, idB.country)
        self.assertEqual(self.a.state, idB.state)
        self.assertEqual(self.a.location, idB.location)
        self.assertEqual(self.a.org, idB.org)
        self.assertEqual(self.a.org_unit, idB.org_unit)
        self.assertEqual(self.a.email, idB.email)       

    def testSetCertInvalid(self):
        self.a.set_cert("""-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----""")
        self.assertFalse(self.a.asserted)
                        
if __name__ == "__main__":
    unittest.main()
