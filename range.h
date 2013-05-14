/*

   bunny - inline ranging component
   --------------------------------

   Examines 32 bit parameters and classifies them as necessary
   for execution path fingerprinting purposes.

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

#ifndef _HAVE_RANGE_H
#define _HAVE_RANGE_H

/*

   Precise ranging of function variables for bit-level tracking:
 
   Map MININT to bit 0
   Map values <= -2^29 to bit 1
   ...
   Map values <= -2^0 to bit 30
   Map 0 to bit 31
   Map values >= 2^29 to bit 61
   ...
   Map values >= 2^0 to bit 32
   Max MAXINT to bit 62

   Reserve bit 63 for signaling a volatile parameter that
   should be not included in a checksum to begin with.

 */


static inline _u64 RANGE64(_s32 num) {
  _u32 i = 30;

  if (!num) return (1LL << 31);

  if (num < 0) {
    if (num == -0x80000000) return (1LL << 0);
      while (--i && !((-num) & (1 << i)));
    return (1LL << (31 - i));
  }

  if (num == 0x7FFFFFFF) return (1LL << 62);
  while (--i && !(num & (1 << i)));
  return (1LL << (32 + i));

  /* Bit 63 is not used / reserved for RANGE64_VOLATILE */

}

#define RANGE64_VOLATILE (1LL << 63)

/* 

    Dumbed down ranging component for rough fuzzing:

    bit 0 - value is negative
    bit 1 - value is zero
    bit 2 - value is <128
    bit 3 - value is <256
    bit 4 - value is <32768
    bit 5 - value is <65536
    bit 6 - values up to MAXINT

   Reserve bit 63 for signaling a volatile parameter that
   should be not included in a checksum to begin with.

 */
 
static inline _u64 RANGE8(_s32 num) {

  if (num < 0) return (1LL << 0);
  if (!num) return (1LL << 1);
  if (num < 128) return (1LL << 2);
  if (num < 256) return (1LL << 3);
  if (num < 32768) return (1LL << 4);
  if (num < 65536) return (1LL << 5);
  return (1LL << 6);

}


#endif /* ! _HAVE_RANGE_H */
