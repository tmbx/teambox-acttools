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

ifndef LIBKTOOLS_INCLUDE
LIBKTOOLS_INCLUDE=../../libktools/src
endif

ifndef LIBKTOOLS_LIB
LIBKTOOLS_LIB=../../libktools/build
endif

ifndef TAGCRYPT_INCLUDE
TAGCRYPT_INCLUDE=../../tagcrypt
endif

ifndef TAGCRYPT_LIB
TAGCRYPT_LIB=../../tagcrypt/build
endif

all:
	gcc -Wall -g \
	    -I$(LIBKTOOLS_INCLUDE) \
	    -I$(TAGCRYPT_INCLUDE) \
	    -D_GNU_SOURCE \
	    -D__UNIX__ \
	    kpsinstalltool.c -o kpsinstalltool \
	    -lgcrypt -lgpg-error -lpthread -ltagcrypt1 -lktools
	    
clean:
	rm -rf kpsinstalltool
