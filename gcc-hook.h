/*

   bunny - gcc hook code
   ---------------------
   
   This prologue is inserted as-is into the code prior to compilation (but after preprocessing,
   so don't use macros). Note that library functions are in all likelihood not declared yet,
   and may never be. Using them without a declaration may generate warnings, and our own 
   declarations could collide with libc or gcc builtins later on, depending on the system.
   To work around this, we declare our own copies, then alias them to proper library symbols.
   
   We need gcc __attribute__ exensions for this, which is why one of the reasons why we 
   strip -ansi and -std= params from compiler command line. 

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

#ifndef _HAVE_GCC_HOOK_H
#define _HAVE_GCC_HOOK_H

#include "types.h"
#include "config.h"

static _u8* __attribute__((unused)) bunny_hook_code = 

/* Magic spell... */
"static __attribute__((used)) char* __bunny_signature =\n"
  "\"*** bunny-gcc " VERSION " (" __DATE__ " " __TIME__ 
  ") by <lcamtuf@google.com> ***\";\n\n"
/* Aliased library functions we plan on calling... We do not want to call them
   by their proper names, as declarations in system .h files change from time
   to time and from OS to OS - and this could lead to compiler errors. */
#ifdef __CYGWIN__
"extern void* __bunny_sys_shmat(unsigned int id, void* addr, unsigned int flag) __attribute__((alias(\"shmat\")));\n"
"extern int   __bunny_sys_getpid(void)  __attribute__((alias(\"getpid\")));\n"
"extern int   __bunny_sys_yield(void)  __attribute__((alias(\"sched_yield\")));\n"
"extern int   __bunny_sys_atoi(char* par) __attribute__((alias(\"atoi\")));\n"
"extern char* __bunny_sys_getenv(char* par) __attribute__((alias(\"getenv\")));\n"
"extern void  __bunny_sys_signal(unsigned int sig, void* handler) __attribute__((alias(\"signal\")));\n"
"extern void  __bunny_sys_raise(unsigned int sig) __attribute__((alias(\"raise\")));\n"
"extern void  __bunny_memcpy(void* dst, void* src, unsigned int count) __attribute__((alias(\"memcpy\")));\n\n"
#else
"extern void* __bunny_sys_shmat(unsigned int id, void* addr, unsigned int flag) __asm__(\"shmat\");\n"
"extern int   __bunny_sys_getpid(void)  __asm__(\"getpid\");\n"
"extern int   __bunny_sys_atoi(char* par) __asm__(\"atoi\");\n"
"extern int   __bunny_sys_yield(void)  __asm__(\"sched_yield\");\n"
"extern char* __bunny_sys_getenv(char* par) __asm__(\"getenv\");\n"
"extern void  __bunny_sys_signal(unsigned int sig, void* handler) __asm__(\"signal\");\n"
"extern void  __bunny_sys_raise(unsigned int sig) __asm__(\"raise\");\n"
"extern void  __bunny_memcpy(void* dst, void* src, unsigned int count) __asm__(\"memcpy\");\n\n"
#endif /* ^__CYGWIN__ */

/* Atomic ++ and -- operations... ugh, sorry, but couldn't come up with an
   approach that wouldn't get butchered by compiler optimization, yet
   remain platform-independent. */
"static __inline__ void __bunny_inc(volatile signed int* ptr) {\n"
"   __asm__ __volatile__(\"lock incl %0\" :\"=m\" (*ptr): \"m\" (*ptr));\n"
"}\n\n"

"static __inline__ void __bunny_dec(volatile signed int* ptr) {\n"
"   __asm__ __volatile__(\"lock decl %0\" :\"=m\" (*ptr) :\"m\" (*ptr));\n"
"}\n\n"

/* Memory structure prepared by the host tracer (must match message.h) */
"static volatile struct __bunny_shm_t {\n"
"  volatile signed int    lock;\n"
"  volatile unsigned int  length, write_off, read_off;\n"
"  volatile unsigned int  child_crash;\n"
"  volatile signed int    func_quota[16];\n"
"  volatile unsigned char data[0];\n"
"} __attribute__((packed)) *__bunny_shm;\n\n"

/* __bunny_shm is an easy target for fenceposts in global buffers. We
   want to detect this and report a crash, rather than hanging or so.
   We mirror ~__bunny_shm here and quickly check it now and then. */
"static volatile unsigned long __bunny_shm_bkup = (unsigned long)-1;\n\n"

/* Error indicator - do not re-attempt shm attach over and over again. */
"static volatile char  __bunny_failed;\n"

/* Fatal signal handler - register, reset signal handler, pass through.
   Note that CPU-level faults (SIGILL, SIGBUS, SIGFPE, SIGSEGV) will reoccur 
   on their own on return from sighandler, so no need to use raise() and 
   pollute stack traces or inhibit kernel-level SEGV logging. */
#ifdef TRACE_CHILDREN
"static void __bunny_crash(signed int signo) {\n"
"  __bunny_sys_signal(signo,0);\n" /* SIG_DFL */
"  if (__bunny_shm && !__bunny_shm->child_crash)\n"
"     __bunny_shm->child_crash = __bunny_sys_getpid();\n"
"  if (signo != 11 && signo != 8 && signo != 7 && signo != 4)\n"
"    __bunny_sys_raise(signo);\n"
"}\n\n"
#endif /* TRACE_CHILDREN */

/* Append data to a cyclic buffer, taking care of locks and read waits. */
"static void __bunny_append_message(unsigned int mtype, unsigned int pid, void* buffer,unsigned int dlen) {\n"
"  signed int can_write;\n"
   /* Detect memory corruption, force SEGV if spotted. */
"  if (__bunny_shm_bkup != ~(unsigned long)__bunny_shm) *(char*)0x0 = 0;\n"
   /* No SHM block? Try to attach, perform other initialization. */
"  if (!__bunny_shm) {\n"
"    char* shmid;\n"
"    if (__bunny_failed) return;\n"
     /* Install signal handlers. */
#ifdef TRACE_CHILDREN
"    __bunny_sys_signal(4, (void*)__bunny_crash);\n" /* SIGILL  */
"    __bunny_sys_signal(7, (void*)__bunny_crash);\n" /* SIGBUS  */
"    __bunny_sys_signal(8, (void*)__bunny_crash);\n" /* SIGFPE  */
"    __bunny_sys_signal(11,(void*)__bunny_crash);\n" /* SIGSEGV */
#ifdef EXTRA_SIGNALS
"    __bunny_sys_signal(5, (void*)__bunny_crash);\n" /* SIGTRAP */
"    __bunny_sys_signal(6, (void*)__bunny_crash);\n" /* SIGABRT */
"    __bunny_sys_signal(24,(void*)__bunny_crash);\n" /* SIGXCPU */
"    __bunny_sys_signal(25,(void*)__bunny_crash);\n" /* SIGXFSZ */
#endif /* EXTRA_SIGNALS */
#endif /* TRACE_CHILDREN */
"    if ((shmid = __bunny_sys_getenv(\"BUNNY_SHMID\"))"
#ifdef __CYGWIN__
        /* CYGWIN=server must be set for SHM to work */
        " && __bunny_sys_getenv(\"CYGWIN\")" 
#endif /* __CYGWIN__ */
        ") {\n"
"      __bunny_shm = (struct __bunny_shm_t*) __bunny_sys_shmat(__bunny_sys_atoi(shmid), 0, 0);\n"
"      if ((long)__bunny_shm == -1) __bunny_shm = 0;\n"
"      __bunny_shm_bkup = ~(unsigned long)__bunny_shm;\n"
"    }\n" /* Otherwise fall through with __bunny_shm == 0 */
"    if (!__bunny_shm) { __bunny_failed = 1; return; }\n"
"  }\n"
   /* If dealing with ENTRY message, decrease output counter; 1^30 = infty; we use 16 
      func_quota buckets to minimize the risk of scheduler-caused differences in truncated
      multi-thread paths. */
"  if (mtype == 0xc0010010 && __bunny_shm->func_quota[pid & 15] != (1<<30))\n"
"    __bunny_dec(__bunny_shm->func_quota + (pid & 15));\n"
"  if (__bunny_shm->func_quota[pid & 15] < 0) return;\n"
   /* Check space (ignore race conditions - the amount of space can only increase) */
"  do {\n"
"    can_write = __bunny_shm->read_off - __bunny_shm->write_off;\n"
"    if (can_write <= 0) can_write += __bunny_shm->length;\n"
"    if (can_write > (signed int)dlen) break;\n"
"    __bunny_sys_yield();\n"
"  } while (1);\n"

   /* Grab a lock, double check for concurrent access... */
"  do {\n"
"    while (__bunny_shm->lock) __bunny_sys_yield();\n"
"    __bunny_inc(&__bunny_shm->lock);\n"
"    if (__bunny_shm->lock == 1) break;\n"
"    __bunny_dec(&__bunny_shm->lock);\n"
"  } while (1);\n"
   /* Store message. */
"  if (__bunny_shm->write_off + dlen > __bunny_shm->length) {\n"
"    int copy1 = __bunny_shm->length - __bunny_shm->write_off, dlen2 = dlen - copy1;\n"
"    __bunny_memcpy((char*) __bunny_shm->data + __bunny_shm->write_off, buffer, copy1);\n"
"    buffer = ((char *) buffer) + copy1;\n"
"    __bunny_memcpy((char*) __bunny_shm->data, buffer, dlen2);\n"
"  } else __bunny_memcpy((char*) __bunny_shm->data + __bunny_shm->write_off, buffer, dlen);\n"
"  __bunny_shm->write_off = (__bunny_shm->write_off + dlen) % __bunny_shm->length;\n"
  /* W00t - success! */
"  __bunny_dec(&__bunny_shm->lock);\n"
"}\n\n"

/* A generic application-level message sender */
"static int __bunny_send_msg(unsigned int mtype, unsigned int mvalue, void* data,\n"
"                                     unsigned int dlen) {\n"
"  struct __bunny_pkt { unsigned int pid, type, value, data_len; } __attribute__((packed)) pkt;\n"
"  pkt.pid      = __bunny_sys_getpid();\n"
"  pkt.type     = mtype;\n"
"  pkt.value    = mvalue;\n"
"  pkt.data_len = dlen;\n"
"  __bunny_append_message(mtype,pkt.pid,&pkt,sizeof(pkt));\n"
"  if (dlen) __bunny_append_message(0,pkt.pid,data,dlen);\n"
"  return 0;\n"
"}\n\n"

;

#endif /* ! _HAVE_GCC_HOOK_H */
