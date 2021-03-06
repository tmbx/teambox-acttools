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

import os, sys, fcntl, struct, inspect
from Activation import ActivationLockException

__all__ = ['ReadLock', 'WriteLock']

class Lock:
    def __init__(self, lockfile, lockobj = None):
        self._refcnt = 0
        self._lockfile = lockfile
        self._lock = lockobj

    def locked(self): return self._refcnt > 0

    def take(self): pass

    def unlock(self):
        self._refcnt = self._refcnt - 1
        if self._refcnt == 0:
            fcntl.flock(self._lock, fcntl.LOCK_UN)
            os.unlink(self._lockfile)
            self._lock.close()
            self._lock = None

class _ReadLock(Lock):
    def write_lock(self):
        """Convert this lock into a write lock.  The current lock
        becomes no longer valid."""
        self._refcnt = 0
        self.unlock()
        w = _WriteLock(self._lockfile, lockobj = self._lock)
        return w

    def take(self):
        self._refcnt = self._refcnt + 1
        if self._refcnt == 1:
            try:
                if not self._lock:
                    self._lock = open(self._lockfile, "w")
                else:
                    self._lock.seek(0, os.SEEK_CUR)
                self._lock.write(str(inspect.stack()[1]))
                fcntl.flock(self._lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except IOError, er:
                raise ActivationLockException("Object is in use (%s)." % er)

    def __repr__(self):
        return "<Read Lock on %s (ref: %d)>" % (self._lockfile, self._refcnt)

class _WriteLock(Lock):
    def take(self):
        self._refcnt = self._refcnt + 1
        if self._refcnt == 1:
            try:
                if not self._lock:
                    self._lock = open(self._lockfile, "w")
                else:
                    self._lock.seek(0, os.SEEK_CUR)
                self._lock.write(str(inspect.stack()[1]))
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError, er:
                raise ActivationLockException("Object is in use (%s)." % er)

    def __repr__(self):
        return "<Write Lock on %s (ref: %d)>" % (self._lockfile, self._refcnt)

def ReadLock(lock, lockfile):
    # Check the validity of the previously taken lock.
    if lock and lock.locked() and (lock.__class__ == _ReadLock or lock.__class__ is _WriteLock):
        newlock = lock
    else:
        newlock = _ReadLock(lockfile)
    newlock.take()
    return newlock

def WriteLock(lock, lockfile):
    # Check the validity of a previously taken lock.  We let the
    # caller upgrade from ReadLock to WriteLock.
    if lock and lock.locked() and lock.__class__ is _WriteLock:
        newlock = lock
    elif lock and lock.locked() and lock.__class__ is _ReadLock:
        newlock = lock.write_lock()
    else:
        newlock = _WriteLock(lockfile)
    newlock.take()
    return newlock
