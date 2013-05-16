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
