/*

   bunny - exec wrapper
   --------------------
   
   Traces an executed program in a constrained time frame, collects trace data, 
   outputs path execution and parameter value hashes and a binary log to fd 99. 
   Output is not human-readable - to be invoked internally by other tracer 
   components only.
  
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
  	    
	    
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef __FreeBSD__
#  include <getopt.h>
#endif /* !__FreeBSD__ */

#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sched.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "nlist.h"
#include "message.h"
#include "range.h"

static FILE* outfile;
#define outf(x...) fprintf(outfile,x)

static struct shm_record *shmreg;

struct proc_state {
  _u32 pid,				/* Process identifier              */
       func_count;			/* Number of functions             */
  _s32 nest;			    	/* Nest level                      */
  struct naive_list funclist; 	    	/* Function call list              */
  struct naive_list_int nestlist;   	/* Function nest level list        */
  struct naive_list_int paramlist;	/* Collected parameters            */
};


static struct proc_state* procs;	/* Traced process table            */
static _u32 proc_cnt, 
	    shmid;

static struct timeval start_time,	/* Trace start time                */
                      last_time;	/* Last trace activity time        */

static _u32 time_limit;			/* Total trace time limit          */ 
static _u32 stuck_limit;		/* Stale process trace time limit  */
static _u32 func_limit;			/* Total number of calls to report */
static _u32 total_calls;		/* Function call counter           */
static _u8  exitflags;			/* EXTTF_*                         */
static _s32 orig_pid;			/* Original PID                    */
static _u8  timeout_done;		/* Timeout handled?                */
static _u8* fault_loc;			/* Most recent fault location      */


/* Locate process entry, create one if requested */
static _s32 get_procentry(_u32 pid,_u8 make_new) {
  _u32 rno;

  for (rno=0;rno<proc_cnt;rno++) 
    if (procs[rno].pid == pid) return rno;

  if (!make_new) return -1;
  
  proc_cnt++;
  
  if ((proc_cnt % ALLOC_CHUNK) == 1) {
    procs = realloc(procs,(proc_cnt + ALLOC_CHUNK) * sizeof(struct proc_state));
    if (!procs) fatal("out of memory");
    memset((void*)(procs+rno),0,sizeof(struct proc_state) * ALLOC_CHUNK);
  }

  procs[rno].pid = pid;
  
  return rno;

}


/* Function entry handler */
static void register_call(_u32 pid, _u8* fname,_u32 pcount) {
  _s32 rno = get_procentry(pid,1);

  /* Record function name and nesting level */    
  DYN_ADD(procs[rno].funclist,fname);
  ADDINT(procs[rno].nestlist,procs[rno].nest);

  procs[rno].nest++;
  procs[rno].func_count++;
  
  gettimeofday(&last_time,0);
  total_calls++;
  
}


/* Function parameter handler */
static void register_param(_u32 pid,_u32 val) {
  _s32 rno = get_procentry(pid,0);
  
  if (rno < 0) fatal("MESSAGE_PARAM for non-existent PID %u",pid);
  
  /* Record parameter data */
  ADDINT(procs[rno].paramlist,val);

}


/* Return value handler */
static void register_return(_u32 pid,_u32 val) {
  _u32 rno = get_procentry(pid,1);
  
  procs[rno].nest--;

  /* Leave a mark on the execution path */
  ADD(procs[rno].funclist,0);
  ADDINT(procs[rno].nestlist,procs[rno].nest);
  /* Record return value */
  ADDINT(procs[rno].paramlist,val);  
    
}


/* Spot instrumentation handler */
static void register_spot(_u32 pid,_u32 val) {
  _u32 rno = get_procentry(pid,1);
    
  /* Record parameter data */
  ADDINT(procs[rno].paramlist,val);  
    
}


static _s32 wait_res;

/* Post-mortem child process accounting */
static _u8 report_kids(void) {
  static _u32 st;
  _s32 i;

  if (wait_res >= 0) {
    wait_res = waitpid(orig_pid,&st,WNOHANG);
    /* Process still running or just done? */
    if (wait_res >= 0) return 0;
  }

  /* Process gone at least a round ago... */

  i = get_procentry(orig_pid,0);

  if (!total_calls) exitflags |= EXITF_NOCALLS;

  /* Detect termination on fault-related signals */
  if (WIFSIGNALED(st)) {
    _u32 sig = WTERMSIG(st);
#ifdef EXTRA_SIGNALS
    if (sig == SIGSEGV || sig == SIGILL  || sig == SIGBUS  || sig == SIGFPE ||
        sig == SIGABRT || sig == SIGTRAP || sig == SIGXCPU || sig == SIGXFSZ)
#else
    if (sig == SIGSEGV || sig == SIGILL  || sig == SIGBUS  || sig == SIGFPE)
#endif /* ^EXTRA_SIGNALS */
      exitflags |= EXITF_CRASH;

    if (i >= 0) {
      register_spot(orig_pid, WTERMSIG(st));
      fault_loc = procs[i].funclist.v[procs[i].funclist.c-1];
    }
      
  } else {
    if (i >= 0) register_spot(orig_pid, WEXITSTATUS(st));
  }

  if (!fault_loc && shmreg->child_crash) {
    _s32 x = get_procentry(shmreg->child_crash,0);
    if (x >= 0) fault_loc = procs[x].funclist.v[procs[x].funclist.c-1];
    exitflags |= EXITF_CRASH;
  }

  /* Kill all registered child processes */
  for (i=0;i<proc_cnt;i++) 
    if (procs[i].pid) kill(procs[i].pid,SIGKILL);

  return 1;
  
}


/* (Signal) Timeout handler - aborts trace if needed */
static void timeout(int sig) {
  struct timeval t;
  _u32 i;

  if (timeout_done) return;

  gettimeofday(&t,0);
  
  i = (t.tv_sec - start_time.tv_sec) * 1000 + (t.tv_usec - start_time.tv_usec) / 1000;
  
  if (i > time_limit) exitflags |= EXITF_TIMEOUT; else {
    i = (t.tv_sec - last_time.tv_sec) * 1000 + (t.tv_usec - last_time.tv_usec) / 1000;
      if (i > stuck_limit) exitflags |= EXITF_STUCK; else return;
  }  

  timeout_done = 1;

#ifdef DEBUG_TRACE
    printf("[bunny-exec] Execution timed out (diff = %u), orig_pid = %u, shmreg->lock = %u...\n",
           i, orig_pid, shmreg->lock);
#endif /* DEBUG_TRACE */

  /* Just let report_kids() take its course, it's safer than calling non-reentrant code
     from here. */

  if (orig_pid > 0) kill(orig_pid,SIGKILL);
  
}


/* Write large block of data at once, regardless of OS buffers. */
static _s32 sure_write(_s32 fd, void* buf, _u32 len) {
  _u32 total = 0;

  do {
    _s32 cur = write(fd,buf,len);
    if (cur <= 0) return cur;
    total += cur;
    len   -= cur;
    buf   += cur;
  } while (len);

  return total;

}



/* Final cleanup and reporting service, called when trace is finished */
static void finalize(void) {
  _u32 rno, i;
  struct bunny_tracedesc msg;
  MD5_CTX ctx;
  _u8 r[16];
  _u32 total_pcount = 0, total_fcount = 0;
  
  msg.exit_status  = exitflags;
  msg.thread_count = proc_cnt;

#ifdef DEBUG_TRACE
  printf("Termination status: 0x%x (",exitflags);

  if (!exitflags) printf("OK"); else {
    if (exitflags & EXITF_TIMEOUT) printf("Timeout");
    if (exitflags & EXITF_CRASH) printf("Crash");
    if (exitflags & EXITF_STUCK) printf("Stuck");
    if (exitflags & EXITF_NOCALLS) printf("Empty");
  }
  
  if (exitflags & (EXITF_TIMEOUT|EXITF_STUCK|EXITF_CRASH))
    printf(":%s",fault_loc ? fault_loc : (_u8*)"?");
  
  printf(")\nProcess count: %u\n",proc_cnt);
#endif /* DEBUG_TRACE */

  /* Report exec path cksum */
  MD5_Init(&ctx);

  for (rno=0;rno<proc_cnt;rno++) {

    for (i=0;i<procs[rno].funclist.c;i++) {
      if (procs[rno].funclist.v[i])
        MD5_Update(&ctx,procs[rno].funclist.v[i],strlen(procs[rno].funclist.v[i]));
      MD5_Update(&ctx,&procs[rno].nestlist.v[i],sizeof(_u32));
    }    

    total_fcount += procs[rno].func_count;

  }

  MD5_Final((char*)r,&ctx);
  
  msg.exec_cksum = *(_u64*)r;
  msg.func_count = total_fcount;

#ifdef DEBUG_TRACE
  printf("Exec flow checksum : %016llx (%u elem)\n",msg.exec_cksum, total_fcount);

  for (rno=0;rno<proc_cnt;rno++) {
    _s32 start = procs[rno].funclist.c - 8;

    if (start < 0) start = 0;
    
    printf("Process %u:\n",rno);
      
    printf("  Call backtrace: ... ");
      
    for (i=start;i<procs[rno].funclist.c;i++) 
      printf("%d:%s ",procs[rno].nestlist.v[i],procs[rno].funclist.v[i] ? procs[rno].funclist.v[i] : (_u8*)"<ret>");
	
    printf("\n");
      
    printf("  Parameter list (%u): ",procs[rno].paramlist.c);
      
    for (i=0;i<((procs[rno].paramlist.c > 32) ? 32 : procs[rno].paramlist.c );i++) 
      printf("0x%x ",procs[rno].paramlist.v[i]);
	
    printf("...\n");

  }
  
#endif /* DEBUG_TRACE */

  for (rno=0;rno<proc_cnt;rno++)
    total_pcount += procs[rno].paramlist.c;

  msg.param_count = total_pcount;
  msg.func_skip   = 0;

  for (i=0;i<16;i++)
    if (shmreg->func_quota[i] < 0) msg.func_skip -= shmreg->func_quota[i]; /* += - */

  if (fault_loc && (exitflags & (EXITF_TIMEOUT|EXITF_STUCK|EXITF_CRASH)))
    msg.fault_len = strlen(fault_loc); else msg.fault_len = 0;

  if (write(99, &msg, sizeof(msg)) != sizeof(msg))
    fatal("short control write to fd #99");

  if (msg.fault_len && write(99, fault_loc, msg.fault_len) != msg.fault_len)
    fatal("short fault data write to fd #99");

  for (rno=0;rno<proc_cnt;rno++) 
    if (procs[rno].paramlist.c) {
      if (sure_write(99,procs[rno].paramlist.v, procs[rno].paramlist.c * sizeof(_u32)) !=
         procs[rno].paramlist.c * sizeof(_u32)) fatal("short param write to fd #99 (%u)",procs[rno].paramlist.c);
    }
    
}


/* Atomic ++ and -- - unfortunately, i386 assembly is required...
   TODO: consider borrowing multi-platform asm/semaphore.h? */
static __inline__ void atomic_inc(volatile int* ptr) {
   __asm__ __volatile__("lock incl %0" :"=m" (*ptr): "m" (*ptr));
}


static __inline__ void atomic_dec(volatile int* ptr) {
   __asm__ __volatile__("lock decl %0" :"=m" (*ptr) :"m" (*ptr));
}



/* Handle SHM, yielding if no data available (unfortunately, wake up on
   dirty pages is not available everywhere). */
static _u8 read_shm(void* ptr, _u32 siz) {
  _s32 avail;

  /* Races here are OK, because the amount of data to be read can only increase
     with time. */

  do {
    avail = shmreg->write_off - shmreg->read_off;
    if (avail < 0) avail += shmreg->length;
    if (avail >= siz) break;
    if (report_kids()) return 1;
    sched_yield();
  } while (1);

  do {
    while (shmreg->lock)
      if (report_kids()) return 1; else sched_yield();
    atomic_inc(&shmreg->lock);
    if (shmreg->lock == 1) break;
    atomic_dec(&shmreg->lock);
    if (shmreg->lock < 0 || shmreg->lock > 1)
      fatal("SHM spinlock state corrupted (up at %d)",shmreg->lock);
  } while (1);

  if (shmreg->read_off + siz >= shmreg->length) {
    _u32 copy1 = shmreg->length - shmreg->read_off, siz2 = siz - copy1;
    memcpy(ptr, (void*) shmreg->data + shmreg->read_off, copy1);
    ptr += copy1;
    memcpy(ptr, (void*) shmreg->data, siz2);
  } else
    memcpy(ptr, (void*) shmreg->data + shmreg->read_off, siz);

  shmreg->read_off = (shmreg->read_off + siz) % (shmreg->length);

  atomic_dec(&shmreg->lock);

  return 0;

}



/* Execute program in a new process, handle events / errors. */
static void handle_process(_u8* path, _u8** argv) {

  struct bunny_message m;

  orig_pid = vfork();
  if (orig_pid < 0) fatal("unable to spawn a process");

  if (!orig_pid) {  
    execvp(path,(char**)argv);
    pfatal("unable to execute '%s'",path);
  }

  while (!read_shm(&m,sizeof(m))) {

    switch (m.type) {

      case MESSAGE_ENTER: {
          char fname[MAXTOKEN];
          if (m.data_len > MAXTOKEN - 1) fatal("excessively long function name");
          if (read_shm(fname,m.data_len)) goto handle_bailout;
          fname[m.data_len]=0;
          register_call(m.pid, fname, m.value);
        }
        break;

      case MESSAGE_PARAM:
        register_param(m.pid, m.value);
        break;

      case MESSAGE_LEAVE:
        register_return(m.pid, m.value);
        break;

      case MESSAGE_SPOT:
        register_spot(m.pid, m.value);
        break;


      default: fatal("malformed data from traced process (0x%08x)",m.type);

    }

  }

handle_bailout:

  finalize();
  
}


/* Just a generic exit routine */
static void handle_kill(int sig) {
  _u32 i;

#ifdef DEBUG_TRACE
  printf("[bunny-exec] Received signal %u.\n",sig);
#endif /* DEBUG_TRACE */
  
  shmctl(shmid, IPC_RMID, 0);
  
  if (orig_pid > 0) kill(orig_pid,SIGKILL);
  for (i=0;i<proc_cnt;i++) 
    if (procs[i].pid) kill(procs[i].pid,SIGKILL);

  exit(1);
}


/* Set up SHM I/O buffer for the child process. */
static void prepare_shm(void) {
  _u8 buf[128];
  _u32 i;

#ifdef __CYGWIN__
  if (!getenv("CYGWIN")) {
    debug("Sorry, you need to enable SHM support in Cygwin first:\n"
          "  1. Install Cygwin IPC service ('cygserver-config').\n"
          "  2. Launch the service ('net start cygserver').\n"
          "  3. Export 'CYGWIN=server' to your environment.\n");
    exit(1);
  }
#endif /* __CYGWIN__ */
    
  if (!(outfile=fdopen(99,"a"))) fatal("unable to create a FILE object");

  shmid = shmget(0, OUTPUT_BUF + sizeof(struct shm_record), IPC_CREAT | 0600);
  if (shmid < 0) pfatal("unable to get %d kB of shared memory", OUTPUT_BUF / 1024);

  shmreg = shmat(shmid, 0, 0);
  if (!shmreg || (long)shmreg == -1) pfatal("unable to attach shared memory");

  sprintf(buf,"%u",shmid);
  setenv("BUNNY_SHMID",buf,1);

  shmreg->length      = OUTPUT_BUF;
  shmreg->child_crash = 0;

  for (i=0;i<16;i++)
    shmreg->func_quota[i] = func_limit;

}



/* Reset the process for keep-alive operation */
static void reset_state(void) {
  _u32 rno, i;

  exitflags           = 0;
  shmreg->write_off   = 0;
  shmreg->read_off    = 0;
  shmreg->lock        = 0;
  shmreg->child_crash = 0;

  wait_res = 0;

  for (i=0;i<16;i++)
    shmreg->func_quota[i] = func_limit;

  /* ignore errors */
  lseek(0,0,SEEK_SET);

  for (rno=0;rno<proc_cnt;rno++) {
    DYN_FREE(procs[rno].funclist);
    FREEINT(procs[rno].nestlist);
    FREEINT(procs[rno].paramlist);
  }

  proc_cnt  = 0;
  orig_pid  = 0;
  fault_loc = 0;

  free(procs);
  procs = 0;

}


static volatile _u8 keepalive_cont;

/* Continuation request callback */
static void handle_input_cont(int sig) {
  keepalive_cont = 1;
}


/* Wait for keepalive signal */
static _u8 reset_wait_keepalive(void) {
  reset_state();
  while (!keepalive_cont) sched_yield();
  return 1;
}


/* Disable timeouts */
static void disable_timers(void) {
  struct itimerval it;

  signal(SIGALRM,SIG_IGN);
  it.it_interval.tv_sec = 0;
  it.it_interval.tv_usec = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL,&it,0);

}


/* Prepare signal handlers, timeouts, etc... */
static void setup_signals(void) {
  struct itimerval it;

  keepalive_cont = 0;
  timeout_done   = 0;

  signal(SIGALRM,timeout);
  it.it_interval.tv_sec = 0;
  it.it_interval.tv_usec = 10000;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 10000;
  setitimer(ITIMER_REAL,&it,0);

  /* At least pretend to be nice. */
  signal(SIGTERM,handle_kill);
  signal(SIGINT,handle_kill);
  signal(SIGHUP,handle_kill);  

  signal(SIGUSR1,handle_input_cont);

}


int main(int argc,char** argv) {

  _u8* t, keep_alive;
  _u32 run_cnt = 0;
  
  if (close(dup(99)) || argc == 1   ||
      !(t=getenv("BUNNY_MAXTIME"))  || sscanf(t,"%u",&time_limit) != 1 ||
      !(t=getenv("BUNNY_MAXSTUCK")) || sscanf(t,"%u",&stuck_limit) != 1 ||
      !(t=getenv("BUNNY_MAXFUNC"))  || sscanf(t,"%u",&func_limit) != 1)
    fatal("not a standalone program");

#ifdef DEBUG_TRACE
  setbuffer(stdout,0,0);
#endif /* DEBUG_TRACE */

  keep_alive = (getenv("BUNNY_KEEPALIVE") != 0);

  unsetenv("BUNNY_KEEPALIVE");
  unsetenv("BUNNY_MAXFUNC");
  unsetenv("BUNNY_MAXTIME");
  unsetenv("BUNNY_MAXSTUCK");

#ifdef DEBUG_TRACE
  printf("[bunny-exec] Starting up (keepalive=%u).\n", keep_alive);
#endif /* DEBUG_TRACE */

  prepare_shm();

#ifdef DEBUG_TRACE
  printf("[bunny-exec] SHM setup complete.\n");
#endif /* DEBUG_TRACE */

  do {

    gettimeofday(&start_time,0);
    memcpy(&last_time,&start_time,sizeof(struct timeval));
  
    setup_signals();

#ifdef DEBUG_TRACE
    printf("[bunny-exec] Launching '%s'...\n",argv[1]);
#endif /* DEBUG_TRACE */

    handle_process(argv[1],(_u8**)argv+1);

    disable_timers();

    if (!((++run_cnt) % TRUNC_FREQ)) {
      /* Every TRUNC_FREQ execs, truncate stdin/stdout if possible, ignore errors. */
      lseek(1,0,SEEK_SET);
      lseek(2,0,SEEK_SET);
      ftruncate(1,0);
      ftruncate(2,0);
    }

  } while (keep_alive && reset_wait_keepalive());

  fclose(outfile);

  shmctl(shmid, IPC_RMID, 0);  

#ifdef DEBUG_TRACE
  printf("[bunny-exec] Shutdown OK.\n");
#endif /* DEBUG_TRACE */


  exit(0);
  
}

