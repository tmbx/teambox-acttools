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
