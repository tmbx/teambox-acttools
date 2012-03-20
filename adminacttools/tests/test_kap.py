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
