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

from acttools import *

class TestActivator(unittest.TestCase):
    def setUp(self):
        kparams_init()
        self.id_parent = Identity(basedir = "/tmp/teambox_test/", identity_name = "test_parent")
        self.id_parent.country = "CA"
        self.id_parent.state = "Québec"
        self.id_parent.location = "Sherbrooke"
        self.id_parent.org = "Opersys (Parent)"
        self.id_parent.org_unit = None
        self.id_parent.domain = "child.teambox.co"
        self.id_parent.email = ""
        self.id_parent.admin_name = "François-Denis Gonthier"
        self.id_parent.admin_email = ""
        self.id_parent.save()
        
        self.id_child = Identity(basedir = "/tmp/teambox_test/", identity_name = "test_child")
        self.id_child.country = "CA"
        self.id_child.state = "Québec"
        self.id_child.location = "Sherbrooke"
        self.id_child.org = "Opersys (Child)"
        self.id_child.org_unit = None
        self.id_child.domain = "parent.teambox.co"
        self.id_child.email = ""
        self.id_child.admin_name = "François-Denis Gonthier"
        self.id_child.admin_email = ""
        self.id_child.save()

        self.keys_parent = KeySet(basedir = "/tmp/teambox_test", keys_name = "test_parent")
        self.keys_child = KeySet(basedir = "/tmp/teambox_test", keys_name = "test_child")

        write_file("/tmp/csr", self.id_parent.get_CSR())
        os.system(" ".join(["openssl", "x509", "-req",
                            "-in", "/tmp/csr",
                            "-CA", "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_cert.pem",
                            "-CAkey", "/home/fdgonthier/Decrypted/secret/teambox/certs/teambox_kar_sign_privkey_nopwd.pem",
                            "-set_serial", "0",
                            "-out", "/tmp/cert"]))
        self.id_parent.set_cert(read_file("/tmp/cert"))

    def tearDown(self):
        self.id_parent.delete()
        self.id_child.delete()
        self.keys_parent.delete()
        self.keys_child.delete()
           
    def test01New(self):
        act = Activator("/home/fdgonthier/repos/teambox-acttools/adminacttools/tests/test_acts",
                        act_name = "main")
        self.assertEqual("main", act.name)
        self.assertEqual("main", act.identity.id_name)
        self.assertEqual("main", act.keyset.keys_name)
        self.assertTrue(act.parent_identity is None)
        self.assertTrue(act.parent_keyset is None)
        self.assert_(len(act.get_KAR("KPS", "1.3")) > 0)

    def test02NewUnasserted(self):
        act = Activator("/tmp/teambox_test", act_name = "test_new")
        act.identity = self.id_child
        act.keyset = self.keys_parent
        self.assertRaises(ActivationException, act.get_KAR, "KPS", "1.3")
        act.delete()

    def test03New(self):       
        act = Activator(basedir = "/tmp/teambox_test", act_name = "test_new")        
        act.identity = self.id_child
        act.parent_identity = self.id_parent
        act.keyset = self.keys_child
        act.parent_keys = self.keys_parent
        act.save()
        
        self.assert_(len(act.get_KAR("KPS", "1.3")) > 0)

        act2 = Activator(basedir = "/tmp/teambox_test", act_name = "test_new")
        self.assertEqual(act.identity.id_name, act2.identity.id_name)
        self.assertEqual(act.parent_identity.id_name, act2.parent_identity.id_name)
        self.assertEqual(act.keyset.keys_name, act2.keyset.keys_name)
        self.assertEqual(act.parent_keyset.keys_name, act2.parent_keyset.keys_name)
        
        #act.delete()

if __name__ == "__main__":
    unittest.main()
