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
# Workdir.py --- Class that wraps a temporary directory with a few useful functions.
# Copyright (C) 2006-2012 Opersys inc.  All rights reserved.
# Author: François-Denis Gonthier

import os, tarfile, gzip

# Working directory class.
class Workdir:
    """A workdir class is just a tool to allow me to tar a directory
    with stuff in it."""

    def get_uuid(self):
        o = open("/proc/sys/kernel/random/uuid")
        uuid = o.readline().strip()
        o.close
        return uuid

    def __init__(self, base_dir = "/tmp", name = None):
        if not name:
            while True:
               name = self.get_uuid()
               if not os.path.exists(os.path.join(base_dir, name)):
                   break
            self.workdir_name = name
        else:
            self.workdir_name = name
        self.workdir_base = base_dir
        self.workdir_path = os.path.join(self.workdir_base, self.workdir_name)
        os.mkdir(self.workdir_path)

    # Add all the files in the directory.
    def tar(self, name, compressed = False):
        z = None
        t = None
        if compressed:
            z = gzip.GzipFile(name, "w")
            t = tarfile.TarFile(mode = "w", fileobj = z)
        else:
            t = tarfile.TarFile(name, "w")
        files = os.listdir(self.workdir_path)
        for i in files:
            f = os.path.join(self.workdir_path, i)
            if f != name: t.add(f, arcname = i)
        t.close()
        if z: 
            # Problem with unsynched file content has been observed!
            # I blame Ted Tso.
            z.flush()
            os.fsync(z.fileno())
            z.close()

    # Delete the directory.
    def close(self):
        # Make sure we only erase below /tmp.
        if not self.workdir_path.startswith("/tmp"):
            raise Exception("Won't try to erase anything not below /tmp.");
        # Recursively erase things.
        for root, dirs, files in os.walk(self.workdir_path, topdown = False):
            for i in files:
                s = os.path.join(root, i)
                os.unlink(s)
            for i in dirs:
                s = os.path.join(root, i)
                os.rmdir(s)
        os.rmdir(self.workdir_path)

    # Returns the workdir path.
    def path(self):
        return self.workdir_path
