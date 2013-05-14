/*

   bunny - standalone vanilla tracer
   ---------------------------------

   Traces a specified application (previously compiled with bunny-gcc or a compatible
   wrapper) and decodes debug output to human-readable form on fd 99. It's not an
   official part of the test suite, but is provided here for your convenience and for
   debugging purposes. Typical use:
   
   ./bunny-trace ./a.exe 99>&2
   ./bunny-trace ./a.exe 99>output.log

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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sched.h>
#include <signal.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "nlist.h"
#include "message.h"

static FILE* outfile;
#define outf(x...) fprintf(outfile,x)

static struct shm_record *shmreg;

struct proc_state {
  _u32 pid,			/* Process identifier */
       par_left;		/* How many parameters to collect? */
  _s32 nest;			/* Code nest level */
  _u8* func_name;		/* Function name */
  struct naive_list params;	/* Collected parameters */
};


static struct proc_state* procs;
static _u32 proc_cnt;
static _s32 shmid;
static _s32 orig_pid;


/* Visual formatting aid */
static void do_indent(_u32 pid,_s32 level,_s8 cor) {
  _s32 i;

  if (level < 0) {  
    outf("[%05u] %+02d < ", pid,level);
  } else {
    outf("[%05u] %03d ", pid,level);
    for (i=0;i<level+cor;i++) outf("| ");
  }

}


/* 32-bit value prettyprinter */
static _u8* process_val(_s32 val) {
  static _u8 buf[32];
  /* Some heuristics */
  if (val > -1000000 && val < 1000000)
    sprintf(buf,"%d",val);
  else sprintf(buf,"0x%08x",val);
  return buf;
}  


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
				  

/* Function call handler */
static void register_call(_u32 pid, _u8* fname,_u32 pcount) {
  _s32 rno = get_procentry(pid,1);

  if (procs[rno].func_name) fatal("out of sequence MESSAGE_ENTER for PID %u",pid);

  procs[rno].par_left  = pcount;
  DYN_FREE(procs[rno].params);
  
  if (!pcount) {
    do_indent(pid,procs[rno].nest,0);
    outf(".- %s()\n",fname);  
    procs[rno].nest++;
  } else {
    procs[rno].func_name = strdup(fname);
    if (!procs[rno].func_name) fatal("out of memory");
  }
  
}


/* Parameter enumeration handler */
static void register_param(_u32 pid,_u32 val) {
  _s32 rno = get_procentry(pid,0);
  
  if (rno < 0) fatal("MESSAGE_PARAM for non-existent PID %u",pid);
  
  if (!procs[rno].func_name || !procs[rno].par_left) 
    fatal("out of sequence MESSAGE_PARAM for PID %u",pid);

  DYN_ADD(procs[rno].params,process_val(val));
    
  if (!(--procs[rno].par_left)) {
    _u32 i;
    
    do_indent(pid,procs[rno].nest,0);
    
    outf(".- %s(",procs[rno].func_name);
    
    for (i=0;i<procs[rno].params.c;i++)
      outf("%s%s",i ? ", " : "", procs[rno].params.v[i]);
      
    outf(")\n");
    
    DYN_FREE(procs[rno].params);
    free(procs[rno].func_name);
    procs[rno].func_name = 0;
    procs[rno].nest++;

  }
  
}


/* Return value handler */
static void register_return(_u32 pid,_u32 val) {
  _s32 rno = get_procentry(pid,1);
  
  if (procs[rno].func_name)
    fatal("out of sequence MESSAGE_LEAVE for PID %u",pid);

  procs[rno].nest--;
  
  do_indent(pid,procs[rno].nest,0);
    
  outf("`- = %s\n",process_val(val));
    
}


/* On-the-spot instrumentation handler */
static void register_spot(_u32 pid,_u32 val) {
  _u32 rno;
  
  for (rno=0;rno<proc_cnt;rno++) 
    if (procs[rno].pid == pid) break;
  
  if (rno == proc_cnt) fatal("MESSAGE_SPOT for non-existent PID %u",pid);
  
  if (procs[rno].func_name || !procs[rno].nest)
    fatal("out of sequence MESSAGE_SPOT for PID %u",pid);

  do_indent(pid,procs[rno].nest,-1);
    
  outf("+--- %s\n",process_val(val));
    
}



/* Post-mortem child process reporting */
static _u8 report_kids(void) {
  _s32 rno;
  _u32 i;

  static _s32 pid;
  static _u32 st;

  if (pid >= 0) {
    pid = waitpid(orig_pid,&st,WNOHANG);
    /* Process still running or just done? */
    if (pid >= 0) return 0;
  }

  /* Process gone at least a round ago... */

  rno = get_procentry(orig_pid,0);

  if (rno < 0) {

    if (WIFEXITED(st))     
      outf("--- Untraced process %u exited (code=%u) ---\n",orig_pid,WEXITSTATUS(st));
    else 
      outf("--- Untraced process %u killed (signal %u) ---\n",orig_pid,WTERMSIG(st));

  } else {

    if (WIFEXITED(st)) 
      outf("--- Process %u exited (code=%u) ---\n",orig_pid,WEXITSTATUS(st));
    else 
      outf("--- Process %u killed (signal %u) ---\n",orig_pid,WTERMSIG(st));

  }

  if (shmreg->child_crash)
    outf("--- (Child process %u crashed) ---\n",shmreg->child_crash);

  for (i=0;i<proc_cnt;i++) kill(procs[i].pid,SIGKILL);
    
  return 1;
  
}


static __inline__ void atomic_inc(volatile int* ptr) {
   __asm__ __volatile__("lock incl %0" :"=m" (*ptr): "m" (*ptr));
}


static __inline__ void atomic_dec(volatile int* ptr) {
   __asm__ __volatile__("lock decl %0" :"=m" (*ptr) :"m" (*ptr));
}


/* Main IPC handler loop */
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
	   
	   

/* handle_process() - execute program in a new process, handle events / errors. */

static void handle_process(_u8* path, _u8** argv) {
  struct bunny_message m;
  
  orig_pid = fork();
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
	  if (read_shm(fname,m.data_len)) fatal("unable to read function name from process");
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
  
}


/* Die semi-gracefully */
static void handle_kill(int sig) {
  _u32 i;
  shmctl(shmid, IPC_RMID, 0);
  if (orig_pid > 0) kill(orig_pid,SIGKILL);
  for (i=0;i<proc_cnt;i++) kill(procs[i].pid,SIGKILL);
  fflush(outfile);
  debug("--- Tracer exiting on signal %d ---\n",sig);
  exit(1);
}


static void setup_signals(void) {
  /* At least pretend to be nice. */  
  signal(SIGTERM,handle_kill);
  signal(SIGINT,handle_kill);
  signal(SIGHUP,handle_kill);
}  



/* Setup SHM I/O buffer */
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
  
  shmid = shmget(0, OUTPUT_BUF + sizeof(struct shm_record), IPC_CREAT | 0600);
  if (shmid < 0) pfatal("unable to get %d kB of shared memory", OUTPUT_BUF / 1024);  
  
  shmreg = shmat(shmid, 0, 0);
  if (!shmreg || (long)shmreg == -1) pfatal("unable to attach shared memory");

  sprintf(buf,"%u",shmid);
  setenv("BUNNY_SHMID",buf,1);
  
  shmreg->length      = OUTPUT_BUF;
  shmreg->child_crash = 0;

  for (i=0;i<16;i++)
    shmreg->func_quota[i] = (1<<30); /* 1^30 = infty */
}


int main(int argc,char** argv) {

  struct timeval x;
  _u64 st, en;
  _u8 buf[128];

  if (argc == 1) {
    debug("Usage: %s /program/to/trace [ params ]\n",argv[0]);
    exit(1);
  }
 
  prepare_shm(); 
  setup_signals(); 
  
  if (close(dup(99))) {
    debug("NOTE: File descriptor #99 closed, defaulting to stderr instead.\n");
    dup2(2,99);
  }

  if (!(outfile=fdopen(99,"a"))) fatal("unable to create FILE object");
  
  gettimeofday(&x,0);
  st = x.tv_sec * 1000 + x.tv_usec / 1000;

  strftime(buf,128,"%Y/%m/%d %H:%M:%S",localtime((time_t*)&x.tv_sec));

  outf("bunny-trace " VERSION " (" __DATE__ " " __TIME__ ") by <lcamtuf@google.com>\n"
       "+++ Trace of '%s' started at %s +++\n", argv[1], buf);
  
  handle_process(argv[1],(_u8**)argv+1);
  
  gettimeofday(&x,0);
  en = x.tv_sec * 1000 + x.tv_usec / 1000;

  outf("+++ Trace complete (%u.%03u secs) +++\n",(_u32)((en-st)/1000), (_u32)((en-st) % 1000));
  fclose(outfile);
  
  shmctl(shmid, IPC_RMID, 0);
  
  exit(0);
  
}

