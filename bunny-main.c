/*

   bunny - main executable
   -----------------------

   Orchestrates a fuzzing effort with the aid of bunny-exec and bunny-flow.

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

#define __USE_LARGEFILE64

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif /* !O_LARGEFILE */

#include "types.h"
#include "config.h"
#include "debug.h"
#include "nlist.h"
#include "message.h"
#include "range.h"

#define R(x)	(random() % (x))
#define R32()	((random() << 16) ^ random())

static FILE* outfile;

#define outf(x...) do { \
    printf(x); \
    /* Static parameters only, x is inlined twice, but it's so much simpler. */ \
    if (outfile) fprintf(outfile,x); \
  } while (0)

#undef debug
#define debug outf


static _u8  *in_dir,				/* Input directory name           */
	    *out_dir,				/* Output directory name          */
	    *write_file,			/* Data output file, if any       */
	    *inflow_dir,			/* Input flow directory 	  */
	    *outflow_dir;			/* Output flow directory	  */
     
static _s32 flow_pid      = -1,			/* bunny-flow process ID          */
            exec_pid      = -1,			/* bunny-exec process ID          */
	    flow_pipe_cmd = -1,			/* bunny-flow command fd 	  */
	    flow_pipe_ret = -1,			/* bunny-flow response fd	  */
            exec_pipe_ret = -1;			/* bunny-exec response fd	  */

static _u32 write_host,				/* Data output host, if any       */
            write_port,				/* Data output port, if any       */
	    use_udp,				/* Protocol to use                */
	    stall_limit         = 2000,		/* Stalled process timeout        */
	    time_limit          = 5000,		/* General process timeout        */
	    bitflip_inc         = 1,		/* Bitflip stepover               */
	    bitflip_max         = 8,		/* Max bitflip width              */
	    chunk_inc           = 1,		/* Chunk modifier stepover        */
	    chunk_max           = 8,		/* Max chunk size                 */
	    chunk_off_max       = 8,		/* Max chunk offset               */
	    eff_count_max       = 10,		/* Max effector bytes per param   */
	    rand_val_walks      = 8,		/* Random value walks per cycle   */
	    rand_phase_cycles   = 4096,		/* Random fuzz cycles             */
	    rand_phase_stacking = 8,		/* Random operations per cycle    */
	    cycle_branch_limit  = 32,		/* Max new branches per cycle     */
	    cycle_value_limit   = 16,		/* Max new param values per cycle */
	    cal_cycles		= 2,		/* Calibration cycle count        */
            func_limit          = 200,		/* Max number of function calls   */
            cur_cycle,				/* Current fuzzing cycle          */
            epath_cnt,				/* call path count		  */
            ppath_cnt,				/* Patam path count		  */
            epath_ign,				/* Ignored path count             */
            ppath_ign,				/* Ignored path count             */
            fuzz_ign,				/* Fuzz step ignore count         */
	    crash_cnt,				/* Crash condition count	  */
            effect_cnt,				/* Effector count                 */
            usleeps_done,			/* usleep(1.1M) count		  */
            queue_real,				/* Filled queue entries		  */
            size_limit,				/* Fuzzable input size limit      */
            total_queue,			/* Total queue entry count	  */
            rand_seed;				/* Random seed in use             */
	    
static _u8  use_builtin_vals = 1,		/* Rely on builtin Val tables?    */
            use_all8,				/* Use all 8-bit values?          */
            keep_fault,				/* Do not abandon timeouted paths */
            allow_dummy,			/* Permit dummy mode?		  */
            full_range,				/* Use fine-grained ranging.      */
            zero_range,				/* Do not use ranging at all!     */
            skip_rounds,			/* Skip deterministic fuzzing     */
            use_qrand,				/* Randomize queue processing     */
            use_beep;				/* Beep on crash?		  */

static struct naive_list_int   byte_val_list,	/* User defined value tables      */
                               word_val_list,   /* (for various value widths)     */
                               dword_val_list;

static _u64 exec_cnt,				/* Exec counter			  */
            input_cnt;				/* Input generator counter	  */

static _u8** program_args;			/* Arguments for the executed app */


struct bunny_traceitem {			/* Trace session descriptor	  */
  _u32  exit_status;				/* Exit status (EXITF_*)	  */
  _u32  fuzzable,				/* Fuzzable byte count		  */
        thread_count;				/* Number of traced processes     */
  
  _u64  exec_cksum,				/* All-process execution checksum */
        param_cksum;				/* All-process parameter checksum */
	
  _u8*  fault_loc;				/* Fault function name, if any    */

  _u32  param_count;				/* Number of parameters		  */
  _u32* param_data;				/* Parameter values (32-bit)	  */
  _u32  func_skip;				/* Parameter skip count           */
  _u64* param_range;				/* Parameter behavior tracing     */
  _u8*  param_chgmap;              		/* Parameter values (32-bit)	  */

  _u32  eff_lwarn;				/* Last effector position warn    */
  _u32  func_count;				/* Function count (informative)   */

  struct naive_list_int2* eff;			/* Per-param effector pos list    */
  struct naive_list_int   has_eff;		/* Has effector? 		  */

};


static _u8** queue_fn;				/* Trace queue: filenames	  */
static struct bunny_traceitem** queue_ck;	/* Trace queue: reference traces. */
static _u32  queue_len;				/* Trace queue length 		  */
static _u8*  queue_af;				/* New affectors witnessed?       */

static struct naive_list_int64  known_exec[0x1000];
static struct naive_list_ptr    known_exti[0x1000];
static struct naive_list_int64 known_param[0x1000];


/* CYGWIN runtime 'cygserver' compatibility check */
static void check_shm_cap(void) {
#ifdef __CYGWIN__
  if (!getenv("CYGWIN")) {
    outf("Sorry, you need to enable SHM support in Cygwin first:\n"
         "  1. Install Cygwin IPC service ('cygserver-config').\n"
         "  2. Launch the service ('net start cygserver').\n"
         "  3. Export 'CYGWIN=server' to your environment.\n");
    exit(1);
  }
#endif /* __CYGWIN__ */
}


/* Termination signal handler; sending SIGTERM to bunny-flow and bunny-exec
   ensures a proper cleanup of SHM regions and child processes. */
static void handle_sig(int sig) {
  if (flow_pid != -1) kill(flow_pid,SIGTERM);
  if (exec_pid != -1) kill(exec_pid,SIGTERM);
  outf("+++ Fuzzing stopped on signal %d +++\n", sig);
  fclose(outfile);
  exit(1);
}


/* ... */
static void usage(_u8* argv0) {
  outf("%s  [ options ] -- /path/to/traced_app [ ... ]\n\n"

       "Mandatory job parameters:\n"
       "  -i dir	- fuzzer input data directory\n"
       "  -o dir	- output directory (crash cases)\n\n"
       
       "Non-standard output control:\n"
       "  -f file	- write data to file\n"
       "  -t host:port  - send data to a TCP service\n"
       "  -u host:port  - send data to a UDP service\n"
       "  -l port       - wait for a local TCP client\n\n"

       "Execution control:\n"
       "  -s nn		- no-action execution time limit          [2000 ms]\n"
       "  -x nn         - total execution time limit              [5000 ms]\n"
       "  -d            - allow 'dummy' mode with no instrumentation\n\n"
       
       "Fuzzing process control:\n"
       "  -B nn[+s]	- maximum bitflip length, +stepover           [8+1]\n"
       "  -C nn[+s]	- maximum chunk operation size, +stepover     [8+1]\n"
       "  -O nn		- chunk offset limit                            [8]\n"
       "  -E nn		- per-parameter effector size limit            [10]\n"
       "  -X b:nn       - add a custom pattern walk value\n"
       "  -Y nn		- number of random pattern walk cyclces         [8]\n"
       "  -R nn		- random exploration repeat count            [2096]\n"
       "  -S nn		- random exploration stacking count             [8]\n"
       "  -N nn		- new call path limit per fuzzing round        [32]\n"
       "  -P nn		- new function parameter limit per round       [16]\n"
       "  -L nn         - fuzz calibration cycle count                  [2]\n"
       "  -M nn         - maximum number of function calls to follow  [200]\n"
       "  -F nn         - fuzzable input data size limit          [start*2]\n"
       "  -8            - use all possible 8-bit values in walks\n"
       "  -n            - do not abandon execution paths after a fault\n"
       "  -r            - use fine-grained 64-bit parameter ranging\n"
       "  -z            - do not use parameter ranging at all\n"
       "  -k            - skip deterministic fuzz rounds\n"
       "  -q            - randomize queue processing order\n"
       "  -g            - use audible crash notification\n\n"
       
       "Predictably, a somewhat less cryptic explanation of these parameters\n"
       "is generously provided in the documentation.\n\n", argv0);
  exit(1);
}


/* Concatenate dir + file into a single string. Uses a cyclic buffer -
   subsequent calls to N() will automatically deallocate previous data. */
static _u8* N(_u8* dir, _u8* file) {
  static _u8* fn = 0;
  
  if (fn) free(fn);
  fn = malloc(strlen(dir) + strlen(file) + 2);
  if (!fn) fatal("out of memory");
  
  sprintf(fn,"%s/%s",dir,file);

  return fn;
}


/* Converts pathname into a canonical fully-qualified one, if needed, to
   make symlinks work. */
static _u8* Ncanon( _u8* file) {
  static _u8* fn = 0;
  static char* cwd = 0;
  
  if (file[0] == '/') return file;
  
  if (!cwd) { 
    cwd = getcwd(0,MAXTOKEN);
    if (!cwd) fatal("out of memory");
  }
  
  if (fn) free(fn);
  fn = malloc(strlen(cwd) + strlen(file) + 2);
  if (!fn) fatal("out of memory");
  
  sprintf(fn,"%s/%s",cwd,file);

  return fn;
}
  

/* Opens a main logfile for outf() calls */
static void init_outfile(void) {
  _s32 fd;
  _u8* fn = N(out_dir,"BUNNY.log");
  
  unlink(fn);
  fd = open(fn,O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE,0600);
  if (fd < 0) pfatal("cannot create '%s'",fn);
  outfile = fdopen(fd,"w");
  
}


/* Splash screen */
static void display_info(char** argv, int argc1) {
  time_t t = time(0);
  _u8* ct= ctime(&t);
  _u8* ip = (_u8*)&write_host;

  if (ct[strlen(ct)-1] == '\n') ct[strlen(ct)-1] = 0;
  
  outf("Bunny the Fuzzer - a high-performance instrumented fuzzer by <lcamtuf@google.com>\n"
       "---------------------------------------------------------------------------------\n\n");
       
  outf("  Code version : " VERSION " (" __DATE__ " " __TIME__ ")\n");
  outf("    Start date : %s\n", ct);
  outf("   Target exec : %s\n", argv[0]);
  outf("  Command line : ");
  if (argc1 == 1) outf("<none>"); else {
    _u32 i;
    for (i=1;i<argc1;i++) outf("%s ",argv[i]);
  }
  outf("\n");
  
  outf("   Input files : %s/\n", in_dir);
  outf("   State files : %s/\n", out_dir);
  outf("   Fuzz output : ");
  
  if (!write_file && !write_port) outf("<target stdin>\n");
  else if (write_file) outf("%s\n",write_file);
  else if (!write_host) outf("client on %u/tcp\n",write_port);
  else outf("server at %u.%u.%u.%u %u/%s\n", ip[0], ip[1], ip[2], ip[3],
            write_port, use_udp ? "udp" : "tcp");

  outf("   Random seed : %08x\n",rand_seed);

  outf("  All settings : T=%u,%u B=%u+%u C=%u+%u,%u A=%u X=%u,%u,%u+%u R=%u*%u L%u=%u,%u r%u%u c=%u U%u E=%u f%u k%u F=%u\n\n",
       time_limit, stall_limit, bitflip_max, bitflip_inc, chunk_max,
       chunk_inc, chunk_off_max, eff_count_max, byte_val_list.c,
       word_val_list.c, dword_val_list.c, rand_val_walks, rand_phase_cycles,
       rand_phase_stacking, use_qrand, cycle_branch_limit, cycle_value_limit, full_range, zero_range,
       cal_cycles, use_all8, func_limit, keep_fault, skip_rounds, size_limit);
       
}


/* Issue a generic command to bunny-flow; see message.h for more info */
static _u32 flow_command(_u32 type, _u32 p1, _u32 p2, _u32 p3) {
  _u32 r;
  struct bunny_flowreq f;
  if (type == FLOW_SAVEFILE) fatal("flow_command called with FLOW_SAVEFILE");
  f.type = type;
  f.p1   = p1;
  f.p2   = p2;
  f.p3   = p3;
  
  if (write(flow_pipe_cmd,&f,sizeof(struct bunny_flowreq)) != sizeof(struct bunny_flowreq))
    fatal("unable to communicate with the component (see bunny-flow.out)");
    
  if (read(flow_pipe_ret,&r,sizeof(_u32)) != sizeof(_u32))
    fatal("short response on command 0x%x(%d,%d,%d) (see bunny-flow.out)",type,p1,p2,p3);
    
  if (type != FLOW_GET_FUZZABLE && r)
    fatal("NOK response on command 0x%x(%d,%d,%d) (see bunny-flow.out)",type,p1,p2,p3);
  else
  if (type == FLOW_GET_FUZZABLE && !r)
    fatal("FLOW_GET_FUZZABLE == 0 (see bunny-flow.out)");

  return r;  
}


/* Special handling of FLOW_SAVEFILE command, with a separately transmitted filename */
static void flow_savefile(_u8* fname) {
  _u32 r;
  struct bunny_flowreq f;
  f.type = FLOW_SAVEFILE;
  f.p1   = strlen(fname);
  f.p2   = 0;
  f.p3   = 0;
  
  if (write(flow_pipe_cmd,&f,sizeof(struct bunny_flowreq)) != sizeof(struct bunny_flowreq))
    fatal("unable to communicate with the component (see bunny-flow.out)");

  if (write(flow_pipe_cmd,fname,f.p1) != f.p1)
    fatal("unable to communicate with the component (see bunny-flow.out)");
    
  if (read(flow_pipe_ret,&r,sizeof(_u32)) != sizeof(_u32))
    fatal("short response on FLOW_SAVEFILE (see bunny-flow.out)");
    
  if (r)
    fatal("NOK response on FLOW_SAVEFILE (see bunny-flow.out)");

}


/* Point bunny-flow input to an existing directory. The directory is not copied over, 
   simply symlinked. */
static void point_inflow(_u8* target_dir) {
  if (!inflow_dir) fatal("inflow_dir is NULL");
  unlink(inflow_dir); /* Ignore errors */
  if (!target_dir) target_dir = in_dir;
  if (symlink(Ncanon(target_dir),inflow_dir)) 
    pfatal("unable to symlink %s -> %s",target_dir,inflow_dir);
}


/* Remove all files in bunny-flow output directory. */
static void purge_outflow(void) {
  DIR* d;
  struct dirent* dent;
  _u8 wbuf[MAXTOKEN];
  
  if (!outflow_dir) fatal("inflow_dir is NULL");
  
  if (!(d = opendir(outflow_dir))) pfatal("unable to open %s",outflow_dir);
  
  while ((dent = readdir(d))) {
    if (dent->d_name[0] == '.') continue;
    snprintf(wbuf,MAXTOKEN,"%s/%s",outflow_dir,dent->d_name);
    if (unlink(wbuf)) pfatal("unable to unlink %s\n",wbuf);
  }
  
  closedir(d);
  
}


/* Start up bunny-flow, set up its input and output directories, comm pipes. */
static void start_flow(void) {
  int toflow[2], fromflow[2];  
  _u32 fuzzable;
  
  if (pipe(toflow) || pipe(fromflow)) pfatal("unable to create a pipe");

  inflow_dir = strdup(N(out_dir,".flow-in"));
  point_inflow(in_dir);

  outflow_dir = strdup(N(out_dir,".flow-out"));
  if (!outflow_dir) fatal("out of memory");
  mkdir(outflow_dir,0755); /* Ignore errors */
  purge_outflow();
  
  flow_pid = fork();
  if (flow_pid < 0) pfatal("unable to create a child process");
  
  if (!flow_pid) {
    _u8  *logfile;
    _s32 fd;
    
    logfile = N(out_dir,"bunny-flow.out");
    
    unlink(logfile);
    fd = open(logfile,O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE,0600);
    if (fd >= 0) { dup2(fd, 2); close(fd); }
    
    if (dup2(toflow[0],0) < 0 || dup2(fromflow[1],1) < 0) pfatal("dup2() failed");
    close(toflow[0]); close(toflow[1]);
    close(fromflow[0]); close(fromflow[1]);

#ifdef USE_EXEC_CWD
    if (access("bunny-flow",X_OK))
#endif /* USE_EXEC_CWD */
      execlp("bunny-flow","bunny-flow",inflow_dir,outflow_dir, (char*) NULL);
#ifdef USE_EXEC_CWD
    else 
      execl("./bunny-flow","bunny-flow",inflow_dir,outflow_dir, (char*) NULL);
#endif /* USE_EXEC_CWD */

    pfatal("cannot execute bunny-flow");
    
  }
  
  flow_pipe_cmd  = toflow[1];  
  flow_pipe_ret  = fromflow[0];  
  
  close(toflow[0]);
  close(fromflow[1]);
  
  fuzzable = flow_command(FLOW_GET_FUZZABLE,0,0,0);    
  if (!size_limit) size_limit = 2*fuzzable;

  outf("[+] Flow controller launched, %u bytes fuzzable.\n",fuzzable);
  
}


/* Find a master descriptor for a known execution path */
static struct bunny_traceitem* lookup_exec(_u64 cksum) {
  _u32 pos = cksum & 0xFFF;
  _u32 i;

  for (i=0;i<known_exec[pos].c;i++)
    if (known_exec[pos].v[i] == cksum) 
      return (struct bunny_traceitem*)known_exti[pos].v[i];
  
  return 0;
}


/* Queue a specified directory for later fuzzing cycles. */
static _u32 add_queue(_u8* indir, struct bunny_traceitem* ref) {
  _u32 i;

  for (i=0;i<queue_len;i++) 
    if (!queue_fn[i]) break;

  if (i == queue_len) {
    queue_len++;
    if ((queue_len % ALLOC_CHUNK) == 1) {
      queue_fn = realloc(queue_fn,(queue_len + ALLOC_CHUNK) * sizeof(_u8*));
      queue_ck = realloc(queue_ck,(queue_len + ALLOC_CHUNK) * sizeof(struct bunny_traceitem*));
      queue_af = realloc(queue_af,(queue_len + ALLOC_CHUNK) * sizeof(_u8));
      if (!queue_fn || !queue_ck || !queue_af) fatal("out of memory");
    }

  }

  queue_af[i] = 0;
  queue_ck[i] = ref;
  queue_fn[i] = strdup(indir);

  if (!queue_fn[i]) fatal("out of memory");

  total_queue++;
  queue_real++;

  return i;

}


/* Fetch the first queue entry, and mark this slot as unused, return pathname
   to a testing directory, fill in effector and reference path data. Subsequent
   calls to get_queue free the previously returned dynamic string, too. */
static _u8* get_queue(struct bunny_traceitem** ref, _u8* new_af) {
  static _u8* ret = 0;
  _u32 i, skip = 0;;

  if (!queue_real) return 0;

  if (use_qrand) skip = R(queue_real);

  for (i=0;i<queue_len;i++) 
    if (queue_fn[i] && !skip--) break;

  if (ret) free(ret);

  ret = queue_fn[i];
  queue_fn[i] = 0;

  *ref    = queue_ck[i];
  *new_af = queue_af[i];

  queue_real--;

  return ret;
  
}


/* bunny-exec cannot checksum parameter variations on its own, because
   it does not have all the path calibration data ahead of time (this is
   applied, if available, by run_program()). We can do the checksumming here.
   CRC64 would perhaps be faster, but MD5 is far more robust for all patterns. */
static void do_param_cksum(struct bunny_traceitem* t) {
  MD5_CTX ctx;
  _u8  res[16];

  MD5_Init(&ctx);
  MD5_Update(&ctx,t->param_range,sizeof(_u64) * t->param_count);
  MD5_Final((char*)res,&ctx);

  t->param_cksum = *(_u64*)res;

}


/* Start bunny-exec in keep-alive mode. */
static void launch_exec(_u8* infn) {
  _s32 exec_pipe[2];
  _s32 infd = 0;

  if (infn) {
    infd = open(infn,O_RDONLY|O_LARGEFILE);
    if (infd < 0) pfatal("unable to open %s for reading",infn);
  }

  if (pipe(exec_pipe)) pfatal("unable to create pipe");

  exec_pid = fork();
  if (exec_pid < 0) pfatal("unable to create a child process");
  
  if (!exec_pid) {
    _u8  tmp[64];
    _u8* logfile = N(out_dir,"bunny-exec.out");
    _u32 fd;

    unlink(logfile);
    fd = open(logfile,O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE,0600);

    if (fd >= 0) { 
      dup2(fd, 2); 
#ifdef DEBUG_TRACE
      dup2(fd, 1);
#else
      close(fd);
      fd = open("/dev/null",O_WRONLY);
      if (fd >= 0) dup2(fd,1);
#endif /* ^DEBUG_TRACE */
      close(fd); 
    }
    
    if (dup2(exec_pipe[1],99) < 0) pfatal("dup2() failed");
    close(exec_pipe[0]);
    close(exec_pipe[1]);
    
    if (infn) {
      if (dup2(infd,0) < 0) pfatal("dup2() failed");
      close(infd);
    } else {
      close(0);
      fd = open("/dev/null",O_RDONLY);
      if (fd) fatal("unable to open /dev/null as fd 0");
    }

    sprintf(tmp,"%u",time_limit);
    setenv("BUNNY_MAXTIME",tmp,1);

    sprintf(tmp,"%u",stall_limit);
    setenv("BUNNY_MAXSTUCK",tmp,1);

    sprintf(tmp,"%u",func_limit);
    setenv("BUNNY_MAXFUNC",tmp,1);

    setenv("BUNNY_KEEPALIVE","yes",1);

#ifdef USE_EXEC_CWD
    if (access("bunny-exec",X_OK))
#endif /* USE_EXEC_CWD */
      execvp("bunny-exec",(char**)program_args);
#ifdef USE_EXEC_CWD
      else execv("./bunny-exec",(char**)program_args);
#endif /* USE_EXEC_CWD */

    pfatal("cannot execute bunny-exec"); 
    
  }
  
  close(exec_pipe[1]);
  if (infn) close(infd);

  exec_pipe_ret = exec_pipe[0];
  
}



/* Read large block of data at once, regardless of OS buffer limits.
   Used to communicate with bunny-exec. */
static _s32 sure_read(_s32 fd, void* buf, _u32 len) {
  _u32 total = 0;

  do {
    _s32 cur = read(fd,buf,len);
    if (cur <= 0) return cur;
    total += cur;
    len   -= cur;
    buf   += cur;
  } while (len);

  return total;
  
}


/* Launch a program, apply path profiling data if reference trace is available,
   allocate all the structures necessary, etc... */
static struct bunny_traceitem* run_program(void) {
  struct bunny_traceitem *ret, *ref;
  struct bunny_tracedesc btd;
  _s32 i;
  _u8* infn = 0;
    
  exec_cnt++;
  ret = malloc(sizeof(struct bunny_traceitem));
  if (!ret) fatal("out of memory");

  purge_outflow();
  
  /* Produce input for the traced application. Note that TCP connect()
     will loop until next command on connection refused, so we're cool. */

  if (!write_file && !write_port) {
    infn = N(out_dir,".fake-pipe");
    flow_savefile(infn);
  } else if (write_file)  flow_savefile(write_file);
    else if (!write_host) flow_command(FLOW_TCP_ACCEPT, htons(write_port), 0, 0);
    else flow_command(use_udp ? FLOW_UDP_SEND : FLOW_TCP_CONNECT, write_host, htons(write_port), 0);
  
  if (exec_pid < 0) launch_exec(infn);
    else kill(exec_pid,SIGUSR1);
  
  if (read(exec_pipe_ret,&btd,sizeof(struct bunny_tracedesc)) != sizeof(struct bunny_tracedesc))
    fatal("short trace struct read (see bunny-exec.out)");

  ret->fuzzable     = 0;    
  ret->exit_status  = btd.exit_status;
  ret->thread_count = btd.thread_count;
  ret->exec_cksum   = btd.exec_cksum;
  ret->param_count  = btd.param_count;
  ret->func_count   = btd.func_count;
  ret->func_skip    = btd.func_skip;
  
  /* Grab fault function name, if any */
  if (btd.fault_len) {
    _u8* tmp = malloc(btd.fault_len + 1);
    if (!tmp) fatal("out of memory");
    
    if (read(exec_pipe_ret,tmp,btd.fault_len) != btd.fault_len)
      fatal("short fault location read (see bunny-exec.out)");
      
    tmp[btd.fault_len]  = 0;
    ret->fault_loc      = tmp;
  } else ret->fault_loc = 0;
  
  ret->eff_lwarn    = 0xFFFFFFFF;

  ret->param_data   = malloc(btd.param_count * sizeof(_u32));
  ret->param_range  = malloc(btd.param_count * sizeof(_u64));
  ret->param_chgmap = calloc(1,btd.param_count * sizeof(_u8)); /* zero */

  if (!ret->param_data || !ret->param_range || !ret->param_chgmap) fatal("out of memory");
  
  if (sure_read(exec_pipe_ret,ret->param_data,btd.param_count * sizeof(_u32)) 
      != btd.param_count * sizeof(_u32))
    fatal("short param read, len %u (see bunny-exec.out)",btd.param_count);

  if (allow_dummy)  ret->exit_status &= ~EXITF_NOCALLS;

  ref = lookup_exec(ret->exec_cksum);

  /* If we can look up reference data for checksumming, use it and calculate
     a parameter checksum, also updating the known range for reference
     path; otherwise, just map arguments and default to checksum of 0. */

  if (ref && ref->param_cksum) {

    /* If we're dealing with a crash / stall, and the trace is shorter than
       expected, cut the traced application some slack - on timeouts, there
       is no guarantee that all SHM writes were completed. */

    if ((!btd.exit_status && btd.param_count != ref->param_count) || 
        (btd.exit_status && btd.param_count > ref->param_count))
      fatal("parameter count varies for a known call path %016llx (%u != %u) - bad use of BunnySnoop?", 
        ret->exec_cksum, btd.param_count, ref->param_count);

    for (i=0;i<btd.param_count;i++)
      if (ref->param_range[i] != RANGE64_VOLATILE) {
        _u64 nr = zero_range ? 1 : (full_range ? RANGE64(ret->param_data[i]) : RANGE8(ret->param_data[i]));

        /* Update both the reference data and the current checksum */
        ret->param_range[i]  = nr;

        if (!(ref->param_range[i] & nr)) {
          ref->param_range[i] |= nr;
          ret->param_chgmap[i] = 1;
        }

      } else ret->param_range[i] = RANGE64_VOLATILE;

    do_param_cksum(ret);

  } else {

    for (i=0;i<btd.param_count;i++)
      ret->param_range[i] = zero_range ? 1 : (full_range ? RANGE64(ret->param_data[i]) : RANGE8(ret->param_data[i]));
    
    ret->param_cksum = 0;

  }

  ret->eff  = calloc(1, btd.param_count * sizeof(struct naive_list_int2)); /* zero */
  if (!ret->eff) fatal("out of memory");

  ret->has_eff.c = 0;
  ret->has_eff.v = 0;

  return ret;
  
}


/* Recycle memory allocated by run_program(), should the resulting execution path
   prove to be previously explored and otherwise uninteresting. */
static void discard_context(struct bunny_traceitem* t, _u8 free_t) {
  _u32 i;

  if (!t->param_data) fatal("context freed more than once");

  free(t->param_data);
  free(t->param_range);
  free(t->param_chgmap);
    
  /* To detect access... */
  t->param_data  = 0;
  t->param_range = 0;

  for (i=0;i<t->param_count;i++) FREEINT2(t->eff[i]);

  free(t->eff);
  t->eff = 0;

  FREEINT(t->has_eff);

  if (t->fault_loc) free(t->fault_loc);

  if (free_t) free(t);

}


/* Empty an input directory for a fully processed queue entry. */
static void free_input(_u8* dir,_u8 deldir) {
  DIR* d;
  struct dirent* dent;

  if (!strcmp(in_dir,dir) || !dir[0]) return;

  d = opendir(dir);
  if (!d) pfatal("cannot open '%s' for reading",dir);

  while ((dent = readdir(d))) {
    if (dent->d_name[0] == '.') continue;
    unlink(N(dir,dent->d_name));
  }

  closedir(d);
  if (deldir) {
    _u8* x = strrchr(dir,'/');
    rmdir(dir);
    if (x) { *x = 0; rmdir(dir); }
  }

}


/* Build a new input directory based on current bunny-flow output.
   Note that hard links, not copies of files, are created. */
static _u8* make_input(_u8* prefix) {
  _u8 *curdir, tmp[MAXTOKEN];
  DIR* d;
  struct dirent* dent;
  static _u8 *newdir = 0;

  if (newdir) free(newdir);

  curdir = strdup(N(out_dir,".flow-out"));
  if (!curdir) fatal("out of memory");

  sprintf(tmp,"%s%03llu",prefix, input_cnt / 1000);
  mkdir(N(out_dir,tmp),0755);
  sprintf(tmp,"%s%03llu/%03llu",prefix, input_cnt / 1000, input_cnt % 1000);
  newdir = strdup(N(out_dir,tmp));
  if (!newdir) fatal("out of memory");

  input_cnt++;

  mkdir(newdir,0755);
  free_input(newdir,0);

  d = opendir(curdir);
  if (!d) pfatal("cannot open '%s' for reading",curdir);

  while ((dent = readdir(d))) {
    _u8 *odname;
    if (dent->d_name[0] == '.') continue;

    odname = strdup(N(curdir,dent->d_name));
    if (!odname) fatal("out of memory");

    if (link(odname, N(newdir,dent->d_name)))
      pfatal("cannot link '%s' to '%s/",odname,newdir);

    free(odname);

  }

  closedir(d);
  free(curdir);

  return newdir;

}


/* Register a new execution path; if 'queue' is set, a new queue entry is created, too. */
static _u8 register_new_exec(struct bunny_traceitem* t, _u8 queue) {
  _u8* inp;
  _u32 pos = t->exec_cksum & 0xFFF;
  _u32 i;

  for (i=0;i<known_exec[pos].c;i++)
    if (known_exec[pos].v[i] == t->exec_cksum) return 0;
  
  ADDINT64(known_exec[pos],t->exec_cksum);
  ADDPTR(known_exti[pos],t);
  epath_cnt++;

  t->param_cksum = 0; /* unknown */

  if (queue) {
    inp = make_input("case");
    add_queue(inp,0);
    outf("    + New call path stored at '%s' (c=%016llx).\n",inp,t->exec_cksum);

    if (t->func_skip)
      outf("      >>> Skipped %u function calls (limit is %u, use -M to adjust).\n",t->func_skip,func_limit);

  }

  return 1;
  
}


#define EFF_UNUSED 0xF0000000


/* Register a new effector for a given location in the parameter trace block for the current
   execution path. Merge overlapping blocks, mind the limits. */
static _u8 add_effector(struct bunny_traceitem* t, _u32 param, _u32 bytepos, _u8 bytelen) {
  _u32 i, efflen = 0;

  for (i=0;i<t->eff[param].c;i++) {

    if (t->eff[param].v1[i] == EFF_UNUSED) continue;

    /* New effector fully contained within an existing one. */
    if (t->eff[param].v1[i] <= bytepos && 
        t->eff[param].v1[i] + t->eff[param].v2[i] >= bytepos + bytelen) return 0;

    /* Beginning of eff[param] inside our block, or adjacent to its end;
       or beginning of our block inside eff[param], or adjacent to its end. */

    if ((t->eff[param].v1[i] >= bytepos && t->eff[param].v1[i] <= bytepos + bytelen) ||
        (bytepos >= t->eff[param].v1[i] && bytepos <= t->eff[param].v1[i] + t->eff[param].v2[i])) {

      _u32 newbeg  = (t->eff[param].v1[i] < bytepos) ? t->eff[param].v1[i] : bytepos,
           newend1 = ((t->eff[param].v1[i] + t->eff[param].v2[i]) > (bytepos + bytelen)) ?
                     (t->eff[param].v1[i] + t->eff[param].v2[i]) : (bytepos + bytelen),
           j;

       if (newend1 - newbeg > eff_count_max) {
         if (t->eff_lwarn != param) {
           outf("      >>> Capping function parameter #%u effectors at %u - possible checksum?\n",
                param, eff_count_max);
           t->eff_lwarn = param;
         }
         return 0;
       }

       bytepos = t->eff[param].v1[i] = newbeg;
       bytelen = t->eff[param].v2[i] = newend1 - newbeg;
       effect_cnt++;

       /* Note that we now might have an overlap with another effector located elsewhere on the
          list - better safe than sorry, it's less expensive to check than to dilute fuzzing
          quality; bytepos and bytelen now point to the boundaries of the existing block. */

       for (j=i+1;j != i; j = (j+1) % t->eff[param].c) {

         if ((t->eff[param].v1[j] >= bytepos && t->eff[param].v1[j] <= bytepos + bytelen) ||
             (bytepos >= t->eff[param].v1[j] && bytepos <= t->eff[param].v1[j] + t->eff[param].v2[j])) {

           _u32 newbeg  = (t->eff[param].v1[j] < bytepos) ? t->eff[param].v1[j] : bytepos,
                newend1 = ((t->eff[param].v1[j] + t->eff[param].v2[j]) > (bytepos + bytelen)) ?
                          (t->eff[param].v1[j] + t->eff[param].v2[j]) : (bytepos + bytelen);
 
           bytepos = t->eff[param].v1[i] = newbeg;
           bytelen = t->eff[param].v2[i] = newend1 - newbeg;
           t->eff[param].v1[j] = EFF_UNUSED;
           t->eff[param].v2[j] = 0;

         }

       }

       return 1;

    }

    efflen += t->eff[param].v2[i];

  }

  if (efflen > eff_count_max) {
    if (t->eff_lwarn != param) {
      outf("      >>> Capping function parameter #%u effectors at %u - possible checksum?\n",
            param, eff_count_max);
      t->eff_lwarn = param;
    }
    return 0;
  }

  ADDINT2(t->eff[param],bytepos,bytelen);
  ADDINT(t->has_eff,param);

  effect_cnt++;

  return 1;

}


/* Register a new parameter sequence for a known execution path. Take care of effectors, etc */
static _u8 register_new_param(struct bunny_traceitem* t, _u32 bytepos, _u8 bytelen, _u8 queue, _u8 nexec) {
  struct bunny_traceitem* ref;
  _u64 use_ck;
  _u32 pos, i, got_new = 0;
  _u8* inp;

  /* This is an unknown call path, bail out */
  if (!t->param_cksum) return 0;

  /* Let's find a master call path... */
  ref = lookup_exec(t->exec_cksum);

  use_ck = t->exec_cksum ^ t->param_cksum;
  pos = use_ck & 0xFFF;

  /* This is a known parameter sequence */
  for (i=0;i<known_param[pos].c;i++)
    if (known_param[pos].v[i] == use_ck) return 0;

  ADDINT64(known_param[pos],use_ck);
  ppath_cnt++;

  if (queue) {
    _u32 qno;

    /* Queue the case itself */
    inp = make_input("case");
    qno = add_queue(inp,ref);

    if (bytelen) {

      for (i=0;i<t->param_count;i++) 
        if (t->param_chgmap[i]) {
          _u32 add = add_effector(ref,i,bytepos,bytelen);
          if (add) queue_af[qno] = 1;
          got_new += add;
        }

      if (got_new)
        outf("      Scheduling %u new affector region%s for thorough tests.\n",got_new, (got_new == 1) ? "" : "s" );

    }

    outf("    + New function parameter sequence stored at '%s' (c=%016llx p=%016llx).\n",inp,
          t->exec_cksum,t->param_cksum);

  }

  /* New path; note that 't' does not have to be preserved; only ref is needed. */
  return 1;
  
}


/* Report a crash condition, copy if necessary; the caller is expected to output a
   more detailed description of the trigger next. */
static _u8 check_crash(struct bunny_traceitem* t) {

  if (t->exit_status & (EXITF_CRASH | EXITF_TIMEOUT | EXITF_STUCK)) {
    _u8* fn;

    outf("\n"
         "+++ FAULT CONDITION DETECTED +++\n");

    if (t->exit_status & EXITF_CRASH)    outf("%sDiagnosis : CRASH (died on supplied input)\n", use_beep ? "\x07\x08" : "");
    if (t->exit_status & EXITF_TIMEOUT)  outf("Diagnosis : timeout (no response for %u ms)\n", time_limit);
    if (t->exit_status & EXITF_STUCK)    outf("Diagnosis : stall (no trace output for %u ms)\n", stall_limit);

    fn = make_input("FAULT");
    
    if (t->fault_loc) {
      if (t->func_skip)
        outf("Location  : %s(...) + %u skipped\n",t->fault_loc,t->func_skip);
        else outf("Location  : %s(...)\n",t->fault_loc);
    }
    
    outf("Capture   : %s\n"
         "Trigger   : ", fn);

    /* Registering the path is counterproductive, and will result in 
       incomplete traces being recorded, causing BunnySnoop error
       messages. Just get rid of the thing. */

    discard_context(t,1);
    crash_cnt++;

    return 1;
  }

  return 0;

}


static _u32 reg_execs,
            reg_params; /* Per cycle counter */


/* Implement a non-random walking bitflip fuzz strategy */
static _u8 bitflip_walk(struct bunny_traceitem* t, _u32 flip) {
  _s32 pos, end = t->fuzzable * 8 - flip;

  if (reg_execs > cycle_branch_limit && (zero_range || reg_params > cycle_value_limit)) return 1;

  flow_command(FLOW_RESET,0,0,0);
  
  for (pos=0;pos <= end;pos++) {
    struct bunny_traceitem* n;
    _u8 rne = 0;
        
    if (pos) {
      flow_command(FLOW_BITFLIP,pos-1,1,0);
      flow_command(FLOW_BITFLIP,pos + flip - 1 ,1,0);
    } else
      flow_command(FLOW_BITFLIP,0,flip,0);

    n = run_program();

    if (check_crash(n)) {
      outf("flipping %u bits at bit offset #%u.\n\n",flip,pos);
      if (keep_fault) continue;
      return 1;
    }

    if (reg_execs > cycle_branch_limit) epath_ign++; else
      if ((rne=register_new_exec(n,1))) {
        outf("      Triggered by flipping %u bits at bit offset #%u.\n",flip,pos);
        reg_execs++;
        if (reg_execs > cycle_branch_limit) 
          outf("      >>> Per-cycle call path limit of %u exceeded (use -N to adjust).\n",cycle_branch_limit);
      }

    if (reg_params > cycle_value_limit) ppath_ign++; else
      if (register_new_param(n,pos/8,(flip+7)/8,1,rne)) {
        outf("      Triggered by flipping %u bits at bit offset #%u.\n",flip,pos);
        reg_params++;
        if (reg_params > cycle_value_limit) 
          outf("      >>> Per-cycle parameter sequence limit of %u exceeded (use -P to adjust).\n",cycle_value_limit);
      }
    
    /* Context not saved */
    if (!rne) discard_context(n,1);
    
  }

  return 0;
  
}


/* Implement a non-random walking value set fuzz strategy */
static _u8 valset_walk(struct bunny_traceitem* t, _u8 size) {
  struct naive_list_int* l = 0;
  _u32 val;
  _s32 pos;

  if (reg_execs > cycle_branch_limit && (zero_range || reg_params > cycle_value_limit)) return 1;

  switch (size) {
    case 1: l = &byte_val_list; break;
    case 2: l = &word_val_list; break;
    case 4: l = &dword_val_list; break;
  }

  for (val=0;val < l->c; val++) 
    for (pos=0;pos < (_s32)t->fuzzable - size ;pos++) {
      struct bunny_traceitem* n;
      _s32 rval = 0;
      _u8 rne = 0;

      flow_command(FLOW_RESET,0,0,0);

      switch (size) {
        case 1: flow_command(FLOW_SETBYTE , pos, (rval = (_s8)l->v[val]) , 0); break;
        case 2: flow_command(FLOW_SETWORD , pos, (rval = (_s16)l->v[val]), 0); break;
        case 4: flow_command(FLOW_SETDWORD, pos, (rval = (_s32)l->v[val]), 0); break;
      }

      n = run_program();

      if (check_crash(n)) {
        outf("setting offset #%u to %d (%s).\n\n",pos, rval,
             (size == 1) ? "byte" : (size == 2) ? "word" : "dword" );
        if (keep_fault) continue;
        return 1;
      }

      if (reg_execs > cycle_branch_limit) epath_ign++;
        else if ((rne=register_new_exec(n,1))) {
        outf("      Triggered by setting offset #%u to %d (%s).\n",pos, rval,
             (size == 1) ? "byte" : (size == 2) ? "word" : "dword" );
        reg_execs++;
        if (reg_execs > cycle_branch_limit) 
          outf("      >>> Per-cycle call path limit of %u exceeded (use -N to adjust).\n",cycle_branch_limit);
      }

      if (reg_params > cycle_value_limit) ppath_ign++;
        else if (register_new_param(n,pos,size,1,rne)) {
          outf("      Triggered by setting offset #%u to %d (%s).\n",pos, rval,
               (size == 1) ? "byte" : (size == 2) ? "word" : "dword" );
          reg_params++;
          if (reg_params > cycle_value_limit) 
            outf("      >>> Per-cycle function parameter limit of %u exceeded (use -P to adjust).\n",cycle_value_limit);
        }
    
      /* Context not saved */
      if (!rne) discard_context(n,1);
    
    }

  return 0;
  
}



/* Implement a random walking value set fuzz strategy */
static _u8 valset_rand_walk(struct bunny_traceitem* t, _u8 size) {
  _u32 val;
  _s32 pos;

  if (reg_execs > cycle_branch_limit && (zero_range || reg_params > cycle_value_limit)) return 1;

  for (val=0;val < rand_val_walks; val++) 
    for (pos=0;pos < (_s32)t->fuzzable - size ;pos++) {
      struct bunny_traceitem* n;
      _s32 rval = 0;
      _u8  rne = 0;

      flow_command(FLOW_RESET,0,0,0);

      switch (size) {
        case 1: flow_command(FLOW_SETBYTE , pos, (rval = (_s8)random()) , 0); break;
        case 2: flow_command(FLOW_SETWORD , pos, (rval = (_s16)random()), 0); break;
        case 4: flow_command(FLOW_SETDWORD, pos, (rval = R32()), 0); break;
      }

      n = run_program();

      if (check_crash(n)) {
        outf("setting offset #%u to %d (%s).\n\n",pos, rval,
             (size == 1) ? "byte" : (size == 2) ? "word" : "dword" );
        if (keep_fault) continue;
        return 1;
      }

      if (reg_execs > cycle_branch_limit) epath_ign++;
        else if ((rne=register_new_exec(n,1))) {
        outf("      Triggered by setting offset #%u to %d (%s).\n",pos, rval,
             (size == 1) ? "byte" : (size == 2) ? "word" : "dword" );
        reg_execs++;
        if (reg_execs > cycle_branch_limit) 
          outf("      >>> Per-cycle call path limit of %u exceeded (use -N to adjust).\n",cycle_branch_limit);
      }

      if (reg_params > cycle_value_limit) ppath_ign++;
        else if (register_new_param(n,pos,size,1,rne)) {
          outf("      Triggered by setting offset #%u to %d (%s).\n",pos, rval,
               (size == 1) ? "byte" : (size == 2) ? "word" : "dword" );
          reg_params++;
          if (reg_params > cycle_value_limit) 
            outf("      >>> Per-cycle function parameter limit of %u exceeded (use -P to adjust).\n",cycle_value_limit);
        }
    
      /* Context not saved */
      if (!rne) discard_context(n,1);
    
    }

  return 0;
  
}


/* Implement a walking chunk operation (clone/overwrite/swap) fuzz strategy */
static _u8 chunk_walk(struct bunny_traceitem* t, _u32 oper, _u32 csize) {
  _s32 shift, pos, rev;

  if (reg_execs > cycle_branch_limit && (zero_range || reg_params > cycle_value_limit)) return 1;

  if (oper == FLOW_INSERT && t->fuzzable >= size_limit) {
    outf("      >>> Fuzzable input limit of %u exceeded (use -F to adjust).\n",size_limit);
    return 1;
  }

  /* FLOW_SWAP is symmetrical; the rest should be tested for +/- shifts */

  for (rev=0;rev < 1 + (oper != FLOW_SWAP);rev++) 
    for (shift = 1; shift < chunk_off_max; shift++) {

      _s32 max = t->fuzzable - csize - shift;

      for (pos=0;pos <= max;pos++) {
        struct bunny_traceitem* n;
        _u8 rne = 0;
        _u32 src, dst;
  
        flow_command(FLOW_RESET,0,0,0);

        if (!rev) { src = pos; dst = pos + shift; }
          else { src = pos + shift; dst = pos; }

        flow_command(oper,dst,csize,src);

        n = run_program();

        if (check_crash(n)) {
          outf("%s %u bytes from offset #%u to #%u.\n\n",
            (oper == FLOW_INSERT) ? "cloning" : 
            (oper == FLOW_SWAP) ? "swapping" : "pasting over",
            csize, src, dst);
          if (keep_fault) continue;
          return 1;
        }

        if (reg_execs > cycle_branch_limit) epath_ign++;
          else if ((rne=register_new_exec(n,1))) {
            outf("      Triggered by %s %u bytes from offset #%u to #%u.\n",
              (oper == FLOW_INSERT) ? "cloning" : 
              (oper == FLOW_SWAP) ? "swapping" : "pasting over",
              csize, src, dst);
  
            reg_execs++;
            if (reg_execs > cycle_branch_limit) 
              outf("      >>> Per-cycle call path limit of %u exceeded (use -N to adjust).\n",cycle_branch_limit);
          }

        if (reg_params > cycle_value_limit) ppath_ign++;
          else if (register_new_param(n,0,0,1,rne)) {
            outf("      Triggered by %s %u bytes from offset #%u to #%u.\n",
              (oper == FLOW_INSERT) ? "cloning" : 
              (oper == FLOW_SWAP) ? "swapping" : "pasting over",
              csize, src, dst);
            reg_params++;
            if (reg_params > cycle_value_limit) 
              outf("      >>> Per-cycle function parameter limit of %u exceeded (use -P to adjust).\n",cycle_value_limit);
          }
      
        /* Context not saved */
        if (!rne) discard_context(n,1);
      
      }
  
    }


  return 0;
  
}


/* Implement a walking chunk deletion fuzz strategy */
static _u8 delete_walk(struct bunny_traceitem* t, _u32 csize) {
  _s32  pos, max = t->fuzzable - csize;

  /* Don't delete everything! */
  if (csize >= t->fuzzable) return 0;

  if (reg_execs > cycle_branch_limit && (zero_range || reg_params > cycle_value_limit)) return 1;

  for (pos=0;pos <= max;pos++) {
    struct bunny_traceitem* n;
    _u8 rne = 0;

    flow_command(FLOW_RESET,0,0,0);
    flow_command(FLOW_DELETE,pos,csize,0);

    n = run_program();

    if (check_crash(n)) {
        outf("deleting %u bytes at offset #%u.\n\n",
          csize, pos);
      if (keep_fault) continue;
      return 1;
    }

    if (reg_execs > cycle_branch_limit) epath_ign++;
      else if ((rne=register_new_exec(n,1))) {
        outf("      Triggered by deleting %u bytes at offset #%u.\n",
          csize, pos);
  
        reg_execs++;
        if (reg_execs > cycle_branch_limit) 
          outf("      >>> Per-cycle call path limit of %u exceeded (use -N to adjust).\n",cycle_branch_limit);
      }

    if (reg_params > cycle_value_limit) ppath_ign++;
      else if (register_new_param(n,0,0,1,rne)) {
        outf("      Triggered by deleting %u bytes at offset #%u.\n",
          csize, pos);
        reg_params++;
        if (reg_params > cycle_value_limit) 
          outf("      >>> Per-cycle function parameter limit of %u exceeded (use -P to adjust).\n",cycle_value_limit);
      }
    
    /* Context not saved */
    if (!rne) discard_context(n,1);
    
  }

  return 0;
  
}


/* Implement a random effector-only value set fuzz strategy */
static _u8 eff_valset_walk(struct bunny_traceitem* t) {
  struct naive_list_int* l = 0;
  struct bunny_traceitem* n;
  _u32 i, j, rne = 0, eno;

  for (i=0;i < rand_phase_cycles; i++) {

    flow_command(FLOW_RESET,0,0,0);

    for (j=0;j<rand_phase_stacking;j++) {
      struct naive_list_int2* eff;
      _s32 rval = 0;

      if (reg_execs > cycle_branch_limit && (zero_range || reg_params > cycle_value_limit)) return 1;

      eff = t->eff + t->has_eff.v[R(t->has_eff.c)];

      do { eno = R(eff->c); } while (eff->v1[eno] == EFF_UNUSED);

      if (R(2)) {

        switch (eff->v2[eno]) {
          case 1:  l = &byte_val_list;  break;
          case 2:  l = &word_val_list;  break;
          default: l = &dword_val_list; break;
        }
	
        rval = l->v[R(l->c)];

      } else
        rval = R32();

      switch (eff->v2[eno]) {
        case 1:  rval = (_s8)rval;
                 flow_command(FLOW_SETBYTE , eff->v1[eno], rval, 0); break;
        case 2:  rval = (_s16)rval;
                 flow_command(FLOW_SETWORD , eff->v1[eno], rval, 0); break;
        default: flow_command(FLOW_SETDWORD, eff->v1[eno], rval, 0); break;
      }

      n = run_program();
 
      if (check_crash(n)) {
        outf("setting offset #%u to %d (%s).\n\n",eff->v1[eno], rval,
             (eff->v2[eno] == 1) ? "byte" : (eff->v2[eno] == 2) ? "word" : "dword" );
        if (keep_fault) continue;
        return 1;
      }

      if (reg_execs > cycle_branch_limit) epath_ign++;
        else if ((rne=register_new_exec(n,1))) {
        outf("      Triggered by setting offset #%u to %d (%s).\n",eff->v1[eno], rval,
             (eff->v2[eno] == 1) ? "byte" : (eff->v2[eno] == 2) ? "word" : "dword" );
        reg_execs++;
        if (reg_execs > cycle_branch_limit) 
          outf("      >>> Per-cycle call path limit of %u exceeded (use -N to adjust).\n",cycle_branch_limit);
      }

      if (reg_params > cycle_value_limit) ppath_ign++;
        else if (register_new_param(n,eff->v1[eno],eff->v2[eno],1,rne)) {
          outf("      Triggered by setting offset #%u to %d (%s).\n",eff->v1[eno], rval,
               (eff->v2[eno] == 1) ? "byte" : (eff->v2[eno] == 2) ? "word" : "dword" );
        reg_params++;
        if (reg_params > cycle_value_limit) 
          outf("      >>> Per-cycle function parameter limit of %u exceeded (use -P to adjust).\n",cycle_value_limit);
      }
      
      /* Context not saved */
      if (!rne) discard_context(n,1);

    }

  }

  
  return 0;
  
}


/* Implement a random operation stacking fuzz strategy */
static _u8 random_stack(struct bunny_traceitem* t) {
  struct bunny_traceitem* n;
  _u32 i, j, rne = 0;

  for (i=0;i < rand_phase_cycles; i++) {

    flow_command(FLOW_RESET,0,0,0);

    for (j=0;j<rand_phase_stacking;j++) {
      _u32 fuz = flow_command(FLOW_GET_FUZZABLE, 0, 0, 0);
      _u32 pos, cnt;

      switch (R(8)) {
        case 0:
          flow_command(FLOW_SETBYTE, R(fuz), random(), 0); 
          break;

        case 1:
          if (fuz > 1)
            flow_command(FLOW_SETWORD, R(fuz - 1), random(), 0);
          break;

        case 2:
          if (fuz > 3) 
            flow_command(FLOW_SETDWORD, R(fuz - 3), R32(), 0);
          break;

        case 3:
          pos = R(fuz * 8);
          cnt = R(fuz * 8 - pos) + 1;
          flow_command(FLOW_BITFLIP, pos, cnt, 0); 
          break;

        case 4:
          if (fuz >= size_limit) break;
          pos = R(fuz);
          cnt = (R(fuz-pos) % chunk_max) + 1;
          cnt %= chunk_max;
          flow_command(FLOW_INSERT, pos, cnt, R(fuz));
          break;

        case 5:
          pos = R(fuz);
          cnt = (R(fuz-pos) % chunk_max) + 1;
          flow_command(FLOW_OVERWRITE, pos, cnt, R(fuz));
          break;

        case 6:
          pos = R(fuz);
          cnt = (R(fuz-pos) % chunk_max) + 1;
          flow_command(FLOW_SWAP, pos, cnt, R(fuz));
          break;

        case 7:
          pos = R(fuz);
          cnt = (R(fuz-pos) % chunk_max) + 1;
          if (fuz > cnt) 
            flow_command(FLOW_DELETE, pos, cnt, 0);
          break;

      }

    }

    n = run_program();
  
    if (check_crash(n)) {
      outf("random rearrangement.\n\n");
      if (keep_fault) continue;
      return 1;
    }

    if (reg_execs > cycle_branch_limit) epath_ign++;
      else if ((rne=register_new_exec(n,1))) {
      outf("      Triggered by random rearrangement.\n");
      reg_execs++;
      if (reg_execs > cycle_branch_limit) 
        outf("      >>> Per-cycle call path limit of %u exceeded (use -N to adjust).\n",cycle_branch_limit);
    }

    if (reg_params > cycle_value_limit) ppath_ign++;
      else if (register_new_param(n,0,0,1,rne)) {
      outf("      Triggered by random rearrangement.\n");
      reg_params++;
      if (reg_params > cycle_value_limit) 
        outf("      >>> Per-cycle function parameter limit of %u exceeded (use -P to adjust).\n",cycle_value_limit);
    }
      
    /* Context not saved */
    if (!rne) discard_context(n,1);

  }

  
  return 0;
  
}


/* Main queue handler. Executes calibration cycles if needed, calls all the fuzzing
   strategies. */
static void process_fuzz_main(_u8* dir, struct bunny_traceitem* useref, _u8 eff) {
  struct bunny_traceitem *cal, *ref;
  _u32 exit_status = 0, diff_count = 0;
  _u32 cno, i, par;
  _u8  path_diff = 0;
  _u8  early_bailout = 0;
  _u64 st_exec = exec_cnt;

  point_inflow(dir);
  flow_command(FLOW_RESCAN,0,0,0);
  
  outf("\n=== Fuzzing cycle %u/%u (%s) ===\n\n", cur_cycle, total_queue - 1, dir);

  if (!useref) {

    outf("[+] New call path - process calibration: ");
  
    cal = malloc(cal_cycles * sizeof(struct bunny_traceitem));
    if (!cal) fatal("out of memory");
    ref = cal;
  
    for (cno=0;cno<cal_cycles;cno++) {
      struct bunny_traceitem *tmp;
       
      tmp = run_program();
      memcpy(cal+cno,tmp,sizeof(struct bunny_traceitem));
      exit_status |= tmp->exit_status;
 
      if (exit_status & EXITF_NOCALLS) break;

      if (cno) {

        if (tmp->thread_count != ref->thread_count) path_diff = 1;

        if (cno) 
          if (ref->exec_cksum  != tmp->exec_cksum ||
              ref->param_count != tmp->param_count) path_diff = 1;

      }

      outf(".");
      fflush(stdout);

      /* On the first cycle, sleep for slightly over a second to make sure we spot all
         time(0)-based changes in function parameters. */
      if (!cno && cal_cycles > 1) {
        usleep(1100000);        
        usleeps_done++;
      }
 
      free(tmp);

    }
  
    outf("DONE %s\n", cal_cycles > 1 ? "(full mode)" : " (basic mode)");

    if (!useref && ref->func_skip)
      outf("    >>> Reference skips %u function call%s - over limit of %u (use -M to adjust).\n",ref->func_skip,
           (ref->func_skip == 1) ? "" : "s", func_limit);
    
    if (exit_status) {
    
      outf("[!] WARNING: Anomalous behavior of the traced program detected in calibration phase!\n"
           "    Trace branch will be abandoned to prevent false positives later on.\n"
           "    Branch '%s', fuzzing cycle #%u, condition list: \n", dir, cur_cycle);

      if (exit_status & EXITF_CRASH)    outf("      - Application crashed unexpectedly!\n");
      if (exit_status & EXITF_NOCALLS)  outf("      - Trace log for the application is empty - executable is missing,\n"
                                             "        broken, or not compiled with bunny-gcc? Maybe you need -d option?\n");
      if (exit_status & EXITF_TIMEOUT)  outf("      - Execution time limit exceeded (%u ms, use -x to change).\n", time_limit);
      if (exit_status & EXITF_STUCK)    outf("      - No-op stall time limit exceeded (%u ms, use -s to change).\n", stall_limit);
      return;
       
    }

    if (path_diff) {
      outf("[!] WARNING: Program flow pattern changes arbitrarily for same input in calibration phase!\n"
           "    Trace branch will be abandoned to avoid false positives later on.\n"
           "    Branch '%s', fuzzing cycle #%u.\n", dir, cur_cycle);
      return;
    }

    /* We want to detect any fluctuations, not just range changes, so
       we have to waste some CPU cycles during the calibration process.
       Not a big deal. */

    for (par=0;par < ref->param_count;par++)
      for (cno=1;cno < cal_cycles;cno++)
        if (ref->param_data[par] != cal[cno].param_data[par]) {
          ref->param_range[par] = RANGE64_VOLATILE;
          diff_count++;
          break;
        }

    if (diff_count)
      outf("    Variations detected for %u/%u function parameters.\n",diff_count,ref->param_count);
    else
      outf("    Found %u fixed function parameters in the trace.\n",ref->param_count);

    /* Free calibration data except for ref-> */
    for (cno=1;cno<cal_cycles;cno++)
      discard_context(cal+cno,0);  
    ref = realloc(ref,sizeof(struct bunny_traceitem));
    cal = 0;

    register_new_exec(ref,0);
    
    /* We updated parameter ranges and registered the call path, so let's 
       self-checksum the reference trace */

    do_param_cksum(ref);

    register_new_param(ref,0,0,0,0);

    ref->fuzzable = flow_command(FLOW_GET_FUZZABLE,0,0,0);  

    outf("    Tracing %u process%s, %u functions, %u bytes fuzzable (c=%016llx p=%016llx)\n", 
         ref->thread_count, ref->thread_count == 1 ? "" : "es", ref->func_count,
         ref->fuzzable, ref->exec_cksum, ref->param_cksum);

  } else {

    ref = useref;
    
    ref->param_cksum = 0xBADBADBADBADBAD0LL;
    ref->fuzzable    = flow_command(FLOW_GET_FUZZABLE,0,0,0);  

    outf("[+] Revisiting call path c=%016llx, %u bytes fuzzable, %u functions.\n", 
         ref->exec_cksum, ref->fuzzable, ref->func_count);

  }

  reg_execs  = 0;
  reg_params = 0;

  if (skip_rounds) {
    outf("[!] Rounds 0-7 skipped (-k option in effect).\n");
    goto skip_to_8;
  }

  /* Mini-fuzzing for effector values */

  if (eff) {
    outf("[+] Fuzzing known effectors first (0/8).\n");
    eff_valset_walk(ref);
  }

  /* Actual fuzzing begins here */
  

  outf("[+] Attempting variable window walking bit flipping (1/8).\n");
  
  for (i=1;i <= bitflip_max;i += bitflip_inc) 
    if (bitflip_walk(ref,i)) { early_bailout = 1; goto fuzz_bailout; }

  outf("[+] Attempting walking value pattern set (2/8).\n");

  if (valset_walk(ref,1)) { early_bailout = 1; goto fuzz_bailout; }
  if (valset_walk(ref,2)) { early_bailout = 1; goto fuzz_bailout; }
  if (valset_walk(ref,4)) { early_bailout = 1; goto fuzz_bailout; }

  outf("[+] Attempting walking value randomization (3/8).\n");

  /* If use_all8 is in effect, there's no point in trying random 1-byte values */

  if (!use_all8) 
    if (valset_rand_walk(ref,1)) { early_bailout = 1; goto fuzz_bailout; }

  if (valset_rand_walk(ref,2)) { early_bailout = 1; goto fuzz_bailout; }
  if (valset_rand_walk(ref,4)) { early_bailout = 1; goto fuzz_bailout; }

  outf("[+] Attempting block deletion operations (4/8).\n");

  for (i=1;i <= chunk_max;i += chunk_inc)
    if (delete_walk(ref,i))               { early_bailout = 1; goto fuzz_bailout; }

  outf("[+] Attempting block overwrite operations (5/8).\n");

  for (i=1;i <= chunk_max;i += chunk_inc)
    if (chunk_walk(ref,FLOW_OVERWRITE,i)) { early_bailout = 1; goto fuzz_bailout; }

  outf("[+] Attempting block cloning operations (6/8).\n");

  for (i=1;i <= chunk_max;i += chunk_inc)
    if (chunk_walk(ref,FLOW_INSERT,i))    { early_bailout = 1; goto fuzz_bailout; }

  outf("[+] Attempting block swap operations (7/8).\n");

  for (i=1;i <= chunk_max;i += chunk_inc)
    if (chunk_walk(ref,FLOW_SWAP,i))      { early_bailout = 1; goto fuzz_bailout; }

skip_to_8:

  outf("[+] Attempting random stacking and rearrangement (8/8).\n");
  if (random_stack(ref)) early_bailout = 1;

fuzz_bailout:

  if (!early_bailout) outf("[+] Fuzzing cycle completed successfully (%llu execs).\n",exec_cnt - st_exec);
  else { 
    outf("[!] Fuzzing cycle terminated on abort condition (%llu execs).\n",exec_cnt - st_exec);
    fuzz_ign++;
  }
  
  free_input(dir,1);
  cur_cycle++;

}


/* Custom atoi handler for command-line params */
static _u32 par_atou(_u8* txt,_u8 opt,_u8 takezero) {
  _u32 ret;
  if (sscanf(txt,"%u",&ret) != 1) fatal("malformed -%c option",opt);
  if (!takezero && !ret) fatal("-%c option must not be zero",opt);
  /* A crude sanity check - 100M oughta be enough for everyone */
  if (ret > 100000000) fatal("excessive -%c value",opt);
  return ret;
}



/* Various "interesting" values, see config.h */
static _s32 intvals[] = {
  INT_VAL_LIST
};


/* Populate builtin value sets in accordance with command-line settings
   and byte widths accepted in each set. */
static void init_builtin_vals(void) {
  _u32 i;

   if (use_all8) {
    _s32 add;

    for (add = -128;add <= 127; add++) {
      ADDINT(dword_val_list,add);
      ADDINT(word_val_list,add);
      ADDINT(byte_val_list,add);
    }

    for (i=0;i<sizeof(intvals) / sizeof(_s32);i++)
      if (intvals[i] < -128 || intvals[i] > 127) {
        if (intvals[i] >= -32768 && intvals[i] <= 32767) 
          ADDINT(word_val_list,intvals[i]);
        ADDINT(dword_val_list,intvals[i]);
      }

    return;
  }


  for (i=0;i<sizeof(intvals) / sizeof(_s32);i++) {
    if (intvals[i] >= -128 && intvals[i] <= 127) 
      ADDINT(byte_val_list,intvals[i]);
    if (intvals[i] >= -32768 && intvals[i] <= 32767) 
      ADDINT(word_val_list,intvals[i]);
    ADDINT(dword_val_list,intvals[i]);
  }

}


static void init_random(void) {
  struct timeval tv;
  gettimeofday(&tv,0);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16);
  srandom(rand_seed);
}



/* getopt() and not much more */
int main(int argc, char** argv) {
  _u8* q, ef;
  _u32 st, en;
  _s32 opt;
  struct bunny_traceitem *ref;

  check_shm_cap();
  
  signal(SIGINT,handle_sig);
  signal(SIGHUP,handle_sig);
  signal(SIGPIPE,SIG_IGN);
  signal(SIGTERM,handle_sig);

  while ((opt = getopt(argc,argv,"+i:o:f:t:u:l:s:x:B:C:O:E:L:X:Y:R:S:N:P:M:F:n8drkqgz")) > 0) 
    switch (opt) {
    
      case 'i': {
          /* bunny-flow checks that too, but we want to be user-friendly */
          struct stat st;
	  if (in_dir) fatal("multiple -i options make no sense");
          if (stat(optarg,&st) || !S_ISDIR(st.st_mode) || access(optarg,X_OK|R_OK))
	    fatal("input directory (-i) not found or non-accessible");
          in_dir = optarg;
	}
 	break;

      case 'o': {
          struct stat st;
	  if (out_dir) fatal("multiple -o options make no sense");
          if (stat(optarg,&st) || !S_ISDIR(st.st_mode) || access(optarg,X_OK|R_OK|W_OK))
	    fatal("output directory (-o) not found or non-writable");
          out_dir = optarg;
	}
 	break;
	
      case 'f': 
        if (write_port || write_file) fatal("only one -t / -u / -l option allowed");
        write_file = optarg;
	break;

      case 't': {
          _u8 a[4];
	  use_udp = 0;
	  if (write_port || write_file) fatal("only one -f / -t / -u / -l option allowed");
          if (sscanf(optarg,"%hhu.%hhu.%hhu.%hhu:%u",&a[0],&a[1],&a[2],&a[3],&write_port) != 5 || !write_port || write_port > 65535)
	    fatal("malformed -t parameter");
  	  write_host = *(unsigned int*)a;
	}
	break;

      case 'u': {
          _u8 a[4];
	  use_udp = 1;
	  if (write_port || write_file) fatal("only one -f / -t / -u / -l option allowed");
          if (sscanf(optarg,"%hhu.%hhu.%hhu.%hhu:%u",&a[0],&a[1],&a[2],&a[3],&write_port) != 5 || !write_port || write_port > 65535)
	    fatal("malformed -u parameter");
  	  write_host = *(unsigned int*)a;
	}
	break;

      case 'l': 
        if (write_port || write_file) fatal("only one -f / -t / -u / -l option allowed");
        write_port = par_atou(optarg,opt,0);
        if (write_port > 65355) fatal("malformed -l port number");
	break;
	
      case 's':
        stall_limit = par_atou(optarg,opt,1);
	if (!stall_limit) stall_limit = 60 * 1000;
	break;

      case 'x':
        time_limit = par_atou(optarg,opt,1);
	if (!time_limit) time_limit = 60 * 1000;
	break;
	
      case 'q':
        use_qrand = 1;
	break;

      case '8':
        use_all8 = 1;
	break;

      case 'n':
        keep_fault = 1;
	break;

      case 'd':
	allow_dummy = 1;
	break;

      case 'r':
	full_range = 1;
        if (zero_range) fatal("-r and -z are mutually exclusive");
	break;

      case 'z':
	zero_range = 1;
        if (full_range) fatal("-r and -z are mutually exclusive");
	break;

      case 'k':
	skip_rounds = 1;
	break;

      case 'g':
        use_beep = 1;
        break;

      case 'B':
        bitflip_inc = 1;
	if (sscanf(optarg,"%u:%u",&bitflip_max,&bitflip_inc) < 1) 
	  fatal("malformed -B option");
	if (!bitflip_inc || !bitflip_max || bitflip_inc > bitflip_max)
	  fatal("malformed -B option");
	if (bitflip_max / bitflip_inc > BYTE_CLIMIT)
	  fatal("-B settings would take too many fuzzing cycles");
        break;

      case 'C':
        chunk_inc = 1;
	if (sscanf(optarg,"%u:%u",&chunk_max,&chunk_inc) < 1) 
	  fatal("malformed -C option");
	if (!chunk_inc || !chunk_max || chunk_inc > chunk_max)
	  fatal("malformed -C option");
	if (chunk_max / chunk_inc * chunk_off_max > BYTE_CLIMIT)
	  fatal("-C / -O settings would take too many fuzzing cycles");
        break;
	
      case 'O':
        chunk_off_max = par_atou(optarg,opt,1);
	if (!chunk_off_max) chunk_off_max = 128; else
	if (chunk_max / chunk_inc * chunk_off_max > BYTE_CLIMIT)
	  fatal("-C / -O settings would take too many fuzzing cycles");
        break;
	
      case 'E':
        eff_count_max = par_atou(optarg,opt,0);
        break;

      case 'M':
        func_limit = par_atou(optarg,opt,0);
        break;

      case 'F':
        size_limit = par_atou(optarg,opt,0);
        break;
	
      case 'X': {
          _s64 i;
	  _u32 b;
          if (sscanf(optarg,"%u:%Li",&b,&i) != 2) fatal("malformed -X input");
	  
	  use_builtin_vals = 0;
	  
	  switch (b) {
	    case 1: ADDINT(byte_val_list,i);    break;
	    case 2: ADDINT(word_val_list,i);    break;
	    case 4: ADDINT(dword_val_list,i);   break;
	    default: fatal("incorrect -X byte width");
	  }
	}
	break;

     case 'Y':
       rand_val_walks = par_atou(optarg,opt,1);
       if (rand_val_walks > TOTAL_CLIMIT)
         fatal("-Y setting would take too many fuzzing cycles");
       break;
       
     case 'R':
       rand_phase_cycles = par_atou(optarg,opt,1);
       /* -R and -S do not take long, no TOTAL_CLIMIT check */
       break;

     case 'S':
       rand_phase_stacking = par_atou(optarg,opt,1);
       /* -R and -S do not take long, no TOTAL_CLIMIT check */
       break;
       
     case 'N':
       cycle_branch_limit = par_atou(optarg,opt,0);
       break;       

     case 'P':
       cycle_value_limit = par_atou(optarg,opt,0);
       break;       

     case 'L':
       cal_cycles = par_atou(optarg,opt,0);
       if (cal_cycles > TOTAL_CLIMIT)
         fatal("-L setting would take too many fuzzing cycles");
       break;       
    
      default: usage(argv[0]);

    }
    
  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  if (use_builtin_vals) init_builtin_vals();

  st = time(0);

  init_random();

  /* A bit hackish, but hey. */
  program_args = (_u8**) ( argv + optind - 1 );
  program_args[0] = "bunny-exec";
    
  init_outfile();
  
  display_info(argv + optind, argc - optind);
  
  start_flow();

  add_queue(in_dir,0);

  while ((q = get_queue(&ref,&ef)))
    process_fuzz_main(q,ref,ef);
  
  if (flow_pid > 0) kill(flow_pid,SIGTERM);
  if (exec_pid > 0) kill(exec_pid,SIGTERM);

  en = time(0);
  
  outf("\n"
       "  Fuzz cycles executed : %u (%u partial)\n"
       "    Processes launched : %llu\n"
       "      Fault conditions : %u\n"
       "       Call path count : %u (+%u ignored)\n"
       "  Parameter variations : %u (+%u ignored)\n"
       "     Effector segments : %u\n"
       "    Total running time : %u:%02u:%02u\n"
       "   Average performance : %0.02f execs/sec\n"
       "\n"
       "[+] Exiting gracefully.\n",
       cur_cycle, fuzz_ign, exec_cnt, crash_cnt, epath_cnt, epath_ign, 
       ppath_cnt, ppath_ign, effect_cnt, (en-st)/60/60, ((en-st)/60) % 60,(en-st) % 60,
         ((float)exec_cnt) / (1 + en-st - (11.0 * usleeps_done) / 10 ));

  unlink(N(out_dir,".fake-pipe"));
  unlink(N(out_dir,".flow-in"));
  
  fclose(outfile);
  return 0;
  
}

