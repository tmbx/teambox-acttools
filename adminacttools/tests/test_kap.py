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

from acttools.KAP import *

class KAPTest(unittest.TestCase):
    def test01KAPWrite(self):
        kap = KAPData()
        kap.email_sig_pkey = "tests/source.sig.pkey"
        kap.email_sig_skey = "tests/source.sig.skey"
        kap.email_enc_pkey = "tests/source.enc.pkey"
        kap.key_id = 10
        kap.kdn = "teambox.test.source"
        kap.bundle = "/etc/fstab"
        kap.license = "/etc/fstab"
        write_KAP(kap, "/tmp/kap.bin",
                  teambox_email_skey = "/home/fdgonthier/Decrypted/secret/teambox/keys/teambox_kps_email.sig.skey",
                  encrypt_pkey = "tests/source.enc.pkey")

    def test02KAPRead(self):
        kap = read_KAP("/tmp/kap.bin",
                       teambox_email_pkey = "/home/fdgonthier/Decrypted/secret/teambox/keys/teambox_kps_email.sig.pkey",
                       encrypt_skey = "tests/source.enc.skey")

    def test03KAPStr(self):
        kap = read_KAP("/tmp/kap.bin",
                       teambox_email_pkey = "/home/fdgonthier/Decrypted/secret/teambox/keys/teambox_kps_email.sig.pkey",
                       encrypt_skey = "tests/source.enc.skey")
        print str(kap)

if __name__ == "__main__":
    unittest.main()
