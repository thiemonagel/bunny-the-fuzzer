#
# bunny - Makefile
# ----------------
#
# Author: Michal Zalewski <lcamtuf@google.com>
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

PROGNAME = bunny-gcc bunny-trace bunny-exec bunny-flow bunny-main
CFLAGS	 = -Wall -O3 -funroll-loops -fno-strict-aliasing -ffast-math -Wno-pointer-sign
EX_LIBS  = -lcrypto -lm

# CFLAGS  = -Wall -g -ggdb -g3 -Wno-pointer-sign
# CFLAGS += -DDEBUG_TRACE=1

all: $(PROGNAME)

bunny-gcc: bunny-gcc.c config.h debug.h nlist.h types.h message.h gcc-hook.h $(EXTRA_C)
	$(CC) $(CFLAGS) $@.c $(EXTRA_C) -o $@ $(EX_LIBS) 

bunny-trace: bunny-trace.c config.h debug.h nlist.h types.h message.h $(EXTRA_C)
	$(CC) $(CFLAGS) $@.c $(EXTRA_C) -o $@ $(EX_LIBS) 

bunny-flow: bunny-flow.c config.h debug.h nlist.h types.h message.h $(EXTRA_C)
	$(CC) $(CFLAGS) $@.c $(EXTRA_C) -o $@ $(EX_LIBS) 

bunny-exec: bunny-exec.c config.h debug.h nlist.h types.h message.h range.h $(EXTRA_C)
	$(CC) $(CFLAGS) $@.c $(EXTRA_C) -o $@ $(EX_LIBS) 

bunny-main: bunny-main.c config.h debug.h nlist.h types.h message.h range.h $(EXTRA_C)
	$(CC) $(CFLAGS) $@.c $(EXTRA_C) -o $@ $(EX_LIBS) 

TESTCASE1 = tests/testcase1
TESTCASE2 = tests/testcase2
TESTCASE3 = tests/testcase3

test1: all $(TESTCASE1).c
	./bunny-gcc $(CFLAGS) -w $(TESTCASE1).c -o $(TESTCASE1)
	./bunny-trace $(TESTCASE1) 1>/dev/null

test2: all $(TESTCASE2).c
	./bunny-gcc $(CFLAGS) -w $(TESTCASE2).c -o $(TESTCASE2)
	./bunny-main -i tests/in -o tests/work $(TESTCASE2)

test3: all $(TESTCASE3).c
	./bunny-gcc $(CFLAGS) -w $(TESTCASE3).c -o $(TESTCASE3)
	./bunny-main -i tests/in -o tests/work $(TESTCASE3)

clean:
	rm -rf tests/work/.[a-z]* tests/work/*
	rm -f $(PROGNAME) $(TESTCASE1) $(TESTCASE2) $(TESTCASE3) tests/*.exe *.exe *.o *~ \
		a.out core core.[1-9][0-9]* .bunny-*-* *.stackdump
