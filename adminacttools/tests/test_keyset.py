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

from acttools.KeySet import *

class TestKeySet(unittest.TestCase):
    def setUp(self):
        kparams_init()

    def testNewKeySet(self):
        k = KeySet(basedir = "/tmp/teambox/", keys_name = "test_new")
        self.assertTrue(not k.enc_zero_pkey is None)
        self.assertTrue(not k.enc_zero_skey is None)
        k.delete()

    def testReload(self):
        k1 = KeySet(basedir = "/tmp/teambox/", keys_name = "test_new2")
        self.assertTrue(not k1.enc_zero_pkey is None)
        self.assertTrue(not k1.enc_zero_skey is None)
        k2 = KeySet(basedir = "/tmp/teambox/", keys_name = "test_new2")
        self.assertEqual(k1.enc_zero_pkey, k2.enc_zero_pkey)
        self.assertEqual(k1.enc_zero_skey, k2.enc_zero_skey)
        k1.delete()
        k2.delete()

    def testSetKeyID(self):
        k = KeySet(basedir = "/tmp/teambox/", keys_name = "test_new")
        k.set_keyid(10)
        self.assertTrue(not k.enc_pkey is None)
        self.assertTrue(not k.enc_skey is None)
        self.assertEqual("10", k.enc_pkey.id)
        self.assertEqual("10", k.enc_skey.id)
        k.delete()

    def testSetSigKey(self):
        k = KeySet(basedir = "/tmp/teambox/", keys_name = "test_new")
        (pk, sk) = Key.newPair(Key.SIG_PAIR, "10", "")
        k.set_sig_skey(sk)
        k.set_sig_pkey(pk)
        self.assertTrue(not k.sig_pkey is None)
        self.assertTrue(not k.sig_skey is None)
        k.delete()
        
if __name__ == "__main__":
    unittest.main()
