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

import unittest, sys, os

# Make sure we test local classes first.
sys.path.insert(0, ".")

from kacttools.config import AdminConfig, ClientConfig

class TestAdminConfig(unittest.TestCase):
    def setUp(self):
        self.file_nomap_ini = "tests/test_admin_nomap.ini"
        self.file_map_ini = "tests/test_admin_map.ini"

    def testInit(self):
        obj = AdminConfig(self.file_nomap_ini)
        self.assert_(os.path.exists(obj.key_id_map_path))
        self.assert_(len(obj.read_key_id_map()) == 0)

        if os.path.exists(obj.key_id_map_path):
            os.unlink(obj.key_id_map_path)

    def testMap(self):
        obj = AdminConfig(self.file_map_ini)
        self.assert_(len(obj.read_key_id_map()) > 0)

    def testReadKey(self):
        obj = AdminConfig(self.file_map_ini)
        keymap = obj.read_key_id_map()
        for i in [10, 11, 12]:
            self.assert_(keymap.has_key(i))
        self.assert_(not keymap.has_key(99))

    def testWriteKey(self):
        obj = AdminConfig(self.file_map_ini)
        keymap = obj.read_key_id_map()
        keymap[13] = ""
        obj.write_key_id_map(keymap)
        keymap = None
        keymap = obj.read_key_id_map()
        self.assert_(keymap.has_key(13))
        del keymap[13]
        obj.write_key_id_map(keymap)
        keymap = None
        keymap = obj.read_key_id_map()
        self.assert_(not keymap.has_key(13))

    def testRandomKey(self):
        obj = AdminConfig(self.file_map_ini)
        keymap = obj.read_key_id_map()
        self.assert_(obj.find_random_key_id(keymap))

class TestClientConfig(unittest.TestCase):
    def setUp(self):
        self.test_ini = "tests/test_admin.ini"

    def testInit(self):
        obj = ClientConfig(AdminConfig(self.test_ini), "test.client1")
        obj.read_config()

    def testDataRead(self):
        obj = ClientConfig(AdminConfig(self.test_ini), "test.client1")
        obj.read_config()
        self.assertEqual("org_name.test_client1", obj.org_name)

    def testDataWrite(self):
        pass

if __name__ == "__main__":
    unittest.main()
