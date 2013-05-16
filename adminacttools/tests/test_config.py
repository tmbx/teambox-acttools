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
