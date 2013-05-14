/*

   bunny - message structures
   --------------------------

   Various inter-component communication formats.

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

#ifndef _HAVE_MESSAGE_H
#define _HAVE_MESSAGE_H

#include "types.h"

/*********************************************************************/
/*** COMMUNICATION BETWEEN gcc-hook.h and bunny-trace / bunny-exec ***/
/*********************************************************************/

#define MESSAGE_ENTER		0xc0010010
#define MESSAGE_PARAM		0xc0010020
#define MESSAGE_LEAVE		0xc0010030
#define MESSAGE_SPOT 		0xc0010040

/* Basic log message unit */
struct bunny_message {
  _u32 pid,				/* Reporting process ID         */
       type,				/* MESSAGE_* - report type      */
       value,				/* Reported value / param count */
       data_len;			/* Payload length (fn name)     */
} __attribute__((packed));

/* SHM block descriptor */
struct shm_record {
  volatile signed int   lock;		/* Shared read/write spinlock    */
  volatile unsigned int length,		/* Buffer length (set by tracer) */
                        write_off,	/* Current write head offset     */
                        read_off,	/* Current read head offset      */
                        child_crash;	/* Crash child PID indicator     */
  volatile signed int   func_quota[16]; /* Function output size limit    */
  volatile unsigned char data[0];	/* bunny_message cyclic buffer   */
} __attribute__((packed));

/*******************************************************/
/*** COMMUNICATION BETWEEN bunny-exec and bunny-main ***/
/*******************************************************/

#define EXITF_TIMEOUT           0x01
#define EXITF_CRASH             0x02
#define EXITF_STUCK             0x04
#define EXITF_NOCALLS           0x08
#define EXITF_3RDPARTY		0x10

/* Global status reporting block */
struct bunny_tracedesc {
  _u8  exit_status;			/* EXITF_* - trace status clues */
  _u64 exec_cksum;			/* Execution path MD5 checksum  */
  _u32 fault_len;			/* Fault location name length   */
  _u32 thread_count,			/* Number of traced processes   */
       func_count,			/* Function count		*/
       param_count,			/* Parameter list size          */
       func_skip;			/* Number of skipped functions  */
};					/* (...list follows...)		*/

/*******************************************************/
/*** COMMUNICATION BETWEEN bunny-exec and bunny-main ***/
/*******************************************************/

/* Process control commands */
#define FLOW_RESCAN		1	/* Rescan input directory for changes  */
#define FLOW_RESET		2	/* Discard all active modifications    */
#define FLOW_GET_FUZZABLE	3	/* Return current fuzz data set length */

/* Input manipulation commands */
#define FLOW_BITFLIP		100	/* Flip P2 bits starting at bit pos P1 */
#define FLOW_SETBYTE		101	/* Set byte at pos P1 to val P2        */
#define FLOW_SETWORD		102	/* Set word at pos P1 to val P2        */
#define FLOW_SETDWORD		103	/* Set dwrd at pos P1 to val P2        */
#define FLOW_DELETE		104	/* Delete P2 bytes at pos P1           */
#define FLOW_OVERWRITE		105	/* Overwrite P2 bytes at P1, src at P3 */
#define FLOW_INSERT		106	/* Insert P2 bytes at P1, src at P3    */
#define FLOW_SWAP		107	/* Swap P2 bytes between P1 and P3     */

/* Output writing commands (always saved to output dir) */
#define FLOW_SAVEFILE		1001	/* Write output to named file          */
#define FLOW_TCP_CONNECT	1002	/* Send packets to a TCP service       */
#define FLOW_TCP_ACCEPT		1003	/* Send packets to a local client      */
#define FLOW_UDP_SEND		1004	/* Send packets to a remote UDP port   */

struct bunny_flowreq {
  _u32 type;				/* FLOW_* request code     */
  _u32 p1, p2, p3;			/* Parameters              */
};					/* (...data may follow...) */

/* Response is always just a 32-bit int: 0 means OK, >0 means error. Note:
   with FLOW_GET_FUZZABLE, return is the byte length, not a binary code. */

#endif /* ! _HAVE_MESSAGE_H */
