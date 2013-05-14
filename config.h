/*

   bunny - hardcoded configuration
   -------------------------------

   Author: Michal Zalewski <lcamtuf@google.com>
   Copyright 2007 Google Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#define VERSION		"0.93-beta"

/* Size limit for various input/output tokens */
#define MAXTOKEN	4096

/* Table allocator alloc-ahead chunk; performance (+) / memory (-) trade-off */
#define ALLOC_CHUNK	128

/* Trace output buffer size (keep a multiple of page size) */
#define OUTPUT_BUF      (128 * 4096)


/* With this option enabled, bunny-gcc will inject code to detect crashes in 
   child processes spawned by the originally executed application. Otherwise,
   checks for SIGSEGV and the like are limited strictly to the initial process. */

#define TRACE_CHILDREN  1

/* Have bunny-exec produce human-readable output to bunny-exec.out, and copy
   traced app's stdout there as well? Useful for debugging, but slows things down
   and uses lots of disk space (otherwise, only bunny-exec errors and traced stderr
   will be output to that file). */

//#define DEBUG_TRACE	1

/* Consider crashing on OS-generated signals (as opposed to low-level CPU faults)
   a fault scenario? This covers calls to assert() and abort(), file size or CPU
   quota limits exceeded, etc. */

#define EXTRA_SIGNALS   1

/* Look up bunny-flow and bunny-exec utilities in current working directory.
   This is somewhat less secure, but handy if you do not intend to install the
   program in your $PATH. */

#define USE_EXEC_CWD	1

/* Per-byte fuzzing cycle limit before we complain about the process taking forever */
#define BYTE_CLIMIT	10000

/* Global fuzzing cycle limit? */
#define TOTAL_CLIMIT	1000000

/* bunny-exec log might grow large and trip filesystem limits; to prevent this, we
   truncate it every TRUNC_FREQ runs; adjust this value to get the amount of
   diagnostic data you need. */
#define TRUNC_FREQ      1000

/* List of "interesting values" for byte/word/dword walk testing */
#define INT_VAL_LIST \
  -2147483648LL, /* Overflow signed 32-bit on -- */ \
  -100000000,    /* Large negative number (100M) */ \
  -32769,        /* Overflow signed 16-bit       */ \
  -32768,        /* Overflow signed 16-bit on -- */ \
  -129, 	 /* Overflow signed 8-bit        */ \
  -128,          /* Overflow signed 8-bit on --  */ \
  -1,		 /*                              */ \
   0,		 /*                              */ \
   1,		 /*                              */ \
   16,		 /* One-off common buf size      */ \
   32,		 /* One-off common buf size      */ \
   64,           /* One-off common buf size      */ \
   100,		 /* One-off common buf size      */ \
   127,		 /* Overflow signed 8-bit on ++  */ \
   128,		 /* Overflow signed 8-bit        */ \
   255,		 /* Overflow unsig 8-bit on ++   */ \
   256,		 /* Overflow unsig 8-bit         */ \
   512,		 /* One-off common buf size      */ \
   1000,	 /* One-off common buf size      */ \
   1024,	 /* One-off common buf size      */ \
   4096,	 /* One-off common buf size      */ \
   32767,	 /* Overflow signed 16-bit on ++ */ \
   32768,	 /* Overflow signed 16-bit       */ \
   65535,	 /* Overflow unsig 16-bit on ++  */ \
   65536,	 /* Overflow unsig 16 bit        */ \
   100000000,	 /* Large positive number (100M) */ \
   2147483647	 /* Overflow signed 32-bit on ++ */  


#if OUTPUT_BUF < 4096 || OUTPUT_BUF < (MAXLINE * 2)
#error "OUTPUT_BUF too small"
#endif /* ... */

#endif /* ! _HAVE_CONFIG_H */
