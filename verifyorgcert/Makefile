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

GNUTLS_INCLUDE=/usr/include/gnutls

ifndef LIBKTOOLS_INCLUDE
LIBKTOOLS_INCLUDE=../../libktools/src
endif

ifndef LIBKTOOLS_LIBRARY
LIBKTOOLS_LIBRARY=../../libktools/build
LIBKTOOLS=-lktools
LIBPATH=-L$(LIBKTOOLS_LIBRARY)
else
LIBPATH=
LIBKTOOLS=-lktools0
endif

INCLUDE=-I$(LIBKTOOLS_INCLUDE) -I$(GNUTLS_INCLUDE)

all:
	gcc -D__UNIX__ -Wall -g verifyorgcert.c -o verifyorgcert \
		$(LIBKTOOLS) -lgnutls $(INCLUDE) $(LIBPATH)

clean:
	rm -rf verifyorgcert
