/*

   bunny - flow fuzzing proxy
   --------------------------

   Processes input files, reads fuzzing directives from stdin, and writes output
   as directed. Intended to require no restarts through the entire fuzzing process
   for performance reasons.

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
#include <signal.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sched.h>
#include <errno.h>
#include <sys/stat.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "nlist.h"
#include "message.h"

static _u8 *indir, *outdir;

static struct file_record {
  _u8* fname;
  _u8* data;
  _u8  asis;
  _u32 orig_len,
       cur_len;
  _u8  dirty;
} *infile;

static _u32 infcount,
            orig_fuzzable,
	    cur_fuzzable;

static _u8  workdir[MAXTOKEN];


/* realloc(0,0) == mem, realloc(mem,0) == 0, d'oh */
static inline void* myrealloc(void* ptr,_u32 len) {
  if (!len) len = 1;
  return realloc(ptr,len);
}


/* qsort() callback for struct file_record */
static int inf_sorter(const void* f1, const void* f2) {
  return strcmp(((const struct file_record*)f1)->fname,((const struct file_record*)f2)->fname);
}


/* Reload all entries in input directory, sort them */
static void reload_config(void) {
  DIR* d;
  struct dirent* dent;
  _u32 i;
   
  for (i=0;i<infcount;i++) {
    free(infile[i].fname);
    if (infile[i].data) free(infile[i].data);
  }
  
  if (infile) free(infile);

  infcount = 0;
  infile   = 0;
  orig_fuzzable = 0;
  
  if (chdir(indir) || !(d = opendir(".")))
    pfatal("cannot open '%s' for reading",indir);
    
  while ((dent = readdir(d))) {
    struct stat st;
    _u8* x;
    
    if (dent->d_name[0] == '.') continue;
    
    x = strrchr(dent->d_name,'.');
    
    infile = realloc(infile,(infcount + 1) * sizeof(struct file_record));
    if (!infile) fatal("out of memory");
    
    infile[infcount].asis = (x && !strcmp(x,".keep"));

    infile[infcount].fname = strdup(dent->d_name);
    if (!infile[infcount].fname) fatal("out of memory");
    
    infile[infcount].data  = 0;
    infile[infcount].dirty = 0;
    
    if (access(dent->d_name,R_OK) || stat(dent->d_name,&st))
      pfatal("unable to access '%s/%s'",indir,dent->d_name);
      
    if (!S_ISREG(st.st_mode))
      fatal("'%s/%s' is not a regular file",indir,dent->d_name);

    /* 4 GB total oughta be enough for everybody... */
    infile[infcount].orig_len   = st.st_size;
    infile[infcount].cur_len    = st.st_size;
    if (!infile[infcount].asis) orig_fuzzable += st.st_size;
    
    infcount++;
  }

  closedir(d);
  
  if (!orig_fuzzable)
    fatal("directory '%s' contains no fuzzable entries",indir);

  if (infcount > 1)
    qsort(infile,infcount,sizeof(struct file_record),inf_sorter);

  debug("Loaded directory '%s': %u entries, %u bytes to fuzz\n",indir,infcount,orig_fuzzable);

  if (chdir(workdir))
    pfatal("unable to go back to work directory");

  cur_fuzzable = orig_fuzzable;
  
}


/* Load file payload into memory, if needed */
static void load_data(_u32 rec) {
  _s32 fd;

  if (infile[rec].data) return;
  
  if (chdir(indir)) pfatal("cannot enter '%s'",indir);
  if (rec >= infcount) fatal("rec out of range");

  fd = open(infile[rec].fname,O_RDONLY);
    
  if (fd < 0)
    pfatal("unable to access '%s/%s'",indir,infile[rec].fname);
        
  infile[rec].dirty = 0;
  infile[rec].data  = malloc(infile[rec].orig_len);
  if (!infile[rec].data) fatal("out of memory");
    
  if (infile[rec].orig_len)
    if (read(fd,infile[rec].data,infile[rec].orig_len) != infile[rec].orig_len)
      fatal("short read from '%s/%s'",indir,infile[rec].fname);

  close(fd);

  if (chdir(workdir)) pfatal("unable to go back to work directory");

}


/* Discard all modifications, but do not rescan input dir */
static void reset_state(void) {
  _u32 i;
  for (i=0;i<infcount;i++) {
    /* Do not dealloc as-is files workbuffers, it's pointless unless a 
       reload is requested; clean buffers may stay, too. */
    if (infile[i].asis) continue;
    if (infile[i].dirty && infile[i].data) {
      free(infile[i].data);
      infile[i].data    = 0;
      infile[i].dirty   = 0;
      infile[i].cur_len = infile[i].orig_len;
    }
  }
  cur_fuzzable = orig_fuzzable;
}


/* Find a specified fuzz data offset, resolve to file_no + buffer_offset */
static _u32 lookup_file(_u32 position, _u8 skip_blank, _u32* offset) {
  _u32 i;
  _u32 cpos = 0;
  _s32 last0 = -1;
  
  for (i=0;i < infcount - 1;i++) {
    if (infile[i].asis) continue;
    if (position < cpos + infile[i].cur_len) break;
    if (!infile[i].cur_len && last0 < 0) last0 = i;
      else if (infile[i].cur_len) last0 = -1;
    cpos += infile[i].cur_len;
  }
  
  *offset = position - cpos;
  
  if (!*offset) {
    if (!skip_blank) return last0 > 0 ? last0 : i;
  } else {
    if (position >= cur_fuzzable) *offset = infile[i].cur_len; /* EOF */
  }
  
  return i;

}


/* Copy a possibly non-continuous block of data from input files to a dynamic buffer */
static _u8* get_data(_u32 position, _u32 len,_u8* where) {
  _u32 f, roff;
      
  if (!where) {
    where = malloc(len);
    if (!where) fatal("out of memory");
  }

  if (!len) return where;

  /* Absolutely no data left? Just return zeros */ 
  if (!cur_fuzzable) {
    memset(where, 0, len);
    return where;
  }

  /* Otherwise, just wrap the address space */
  position %= cur_fuzzable;
  
  f = lookup_file(position, 1, &roff);
  load_data(f);
  
  /* Can it be done in a single read? */
  if (roff + len <= infile[f].cur_len) {
    memcpy(where,infile[f].data + roff, len);
  /* Multiple reads needed */
  } else {
    _u32 cancopy = infile[f].cur_len - roff;
    memcpy(where,infile[f].data + roff, cancopy);
    position += cancopy;
    len -= cancopy;
    get_data(position, len, where + cancopy);
  }
  
  return where;

}


/* Overwrtie a region in the fuzz buffer */
static void set_data(_u32 position, _u32 len,_u8* src) {
  _u32 f, roff;

  if (!cur_fuzzable || !len) return;
  position %= cur_fuzzable;
  
  f = lookup_file(position, 1, &roff);
  load_data(f);

  infile[f].dirty = 1;

  if (roff + len <= infile[f].cur_len) {
    memcpy(infile[f].data + roff, src, len);
  } else {
    _u32 cancopy = infile[f].cur_len - roff;
    memcpy(infile[f].data + roff, src, cancopy);
    position += cancopy;
    len -= cancopy;
    set_data(position, len, src + cancopy);
  }
  
}


/* Insert data, resizing the fuzz buffer. */
static void insert_data(_u32 position, _u32 len, _u8* buf) {
  _u32 f, roff;
  
  if (!len) return;

  /* set_data() will wrap otherwise... but accept EOF */
  if (position > cur_fuzzable) position = cur_fuzzable;
  
  f = lookup_file(position, 0, &roff);
  load_data(f);

  infile[f].dirty = 1;  
  
  infile[f].data = realloc(infile[f].data, infile[f].cur_len + len);
  if (!infile[f].data) fatal("out of memory");

  if (roff != infile[f].cur_len)
    memmove(infile[f].data + roff + len, infile[f].data + roff, infile[f].cur_len - roff);

  infile[f].cur_len += len;
  cur_fuzzable += len;
  
  set_data(position,len,buf);    
  
}


/* Delete data, resizing the input buffer */
static void remove_data(_u32 position, _u32 len) {
  _u32 f, roff;

  if (!len) return;

  f = lookup_file(position, 1, &roff);
  load_data(f);
  
  if (roff == infile[f].cur_len) return; /* EOF already */

  infile[f].dirty = 1;
  
  /* Can remove in one operation? */
  if (roff + len <= infile[f].cur_len) {
    if (roff + len < infile[f].cur_len)
      memmove(infile[f].data + roff, infile[f].data + roff + len, infile[f].cur_len - roff);

    infile[f].data = myrealloc(infile[f].data, infile[f].cur_len - len);

    if (!infile[f].data) fatal("out of memory");
    infile[f].cur_len -= len;
    cur_fuzzable -= len;
  } else {
    _u32 candel = infile[f].cur_len - roff;
    /* Remove everything to EOF, repeat */
    infile[f].data = myrealloc(infile[f].data, roff);
    if (!infile[f].data) fatal("out of memory");
    cur_fuzzable -= candel;
    infile[f].cur_len = roff;
    remove_data(position, len - candel);
  }

}


/* Locate and change a single byte in the fuzz buffer */
static void set_byte(_u32 position, _u32 val) {
  _u32 f, roff;
  
  if (!cur_fuzzable) return;
  position %= cur_fuzzable;

  f = lookup_file(position, 1, &roff);
  load_data(f);

  infile[f].dirty = 1;  
  infile[f].data[roff] = val;
}


/* Locate and change a single word in the fuzz buffer */
static void set_word(_u32 position, _u32 val) {
  _u32 f, roff;
  
  if (!cur_fuzzable) return;
  position %= cur_fuzzable;

  f = lookup_file(position, 1, &roff);
  load_data(f);

  infile[f].dirty = 1;  
  
  if (roff + 1 < infile[f].cur_len) 
    *(_u16*)(infile[f].data + roff) = val;
  else {
    /* Assume LE - we're IA32 specific anyway */
    infile[f].data[roff] = val;
    set_byte(position + 1, val >> 8);
  }
}


/* Locate and change a single dword in the fuzz buffer */
static void set_dword(_u32 position, _u32 val) {
  _u32 f, roff;
  
  if (!cur_fuzzable) return;
  position %= cur_fuzzable;

  f = lookup_file(position, 1, &roff);
  load_data(f);

  infile[f].dirty = 1;  
  
  if (roff + 3 < infile[f].cur_len)
    *(_u32*)(infile[f].data + roff) = val;
  else {
    /* Assume LE - we're IA32 specific anyway */
    infile[f].data[roff] = val;
    set_byte(position + 1, val >> 8);
    set_word(position + 2, val >> 16);
  }
  
}


/* Flip a sequence of bits in the fuzz buffer */
static void flip_bits(_u32 bitpos, _u32 bitlen) {
  _u32 f, roff;
  
  if (!cur_fuzzable || !bitlen) return;
  bitpos %= cur_fuzzable * 8;

  f = lookup_file(bitpos / 8, 1, &roff);
  load_data(f);

  infile[f].dirty = 1;  
  
  while (bitlen--) {

    /* Assume LE - we're IA32 specific anyway */
    infile[f].data[roff] ^= 1 << (7 - (bitpos % 8));
    
    if (!(++bitpos % 8)) roff++;

    if (roff >= infile[f].cur_len) {
      f = lookup_file(bitpos / 8, 1, &roff);
      load_data(f);
      infile[f].dirty = 1;  
    }

  }  
  
}

/* A handler for copying data between two locations in the fuzz buffer. */
static void copy_data_ext(_u32 dpos, _u32 len, _u32 spos) {
  _u8* o = get_data(spos,len,0);
  set_data(dpos,len,o);
  free(o);
}


/* Ditto, for insertion */
static void insert_data_ext(_u32 dpos, _u32 len, _u32 spos) {
  _u8* o = get_data(spos,len,0);
  insert_data(dpos,len,o);
  free(o);
}


/* Ditto, for block swap */
static void swap_data_ext(_u32 pos1, _u32 len, _u32 pos2) {
  _u8 *o1 = get_data(pos1,len,0),
      *o2 = get_data(pos2,len,0);
  set_data(pos1,len,o2);
  set_data(pos2,len,o1);
  free(o1);
  free(o2);
}


/* A low-level routine to output all data to output dir and a specified fd */
static void commit_data_fd(_u32 fd) {
  _u32 i;
  _s32 of;

  /* Save a copy to output dir first - chat with the app may go wrong,
     especially over the network, we do not want to lose data. */

  for (i=0;i<infcount;i++) {
  
    load_data(i);

    if (chdir(outdir)) fatal("cannot enter '%s'",outdir);

    unlink(infile[i].fname);

    if (!infile[i].dirty) {
    
      _u8 *fin = malloc(strlen(workdir) + strlen(indir) + strlen(infile[i].fname) + 5);
      if (!fin) fatal("out of memory");
      if (indir[0] == '/') 
        snprintf(fin,MAXTOKEN,"%s/%s", indir, infile[i].fname);
	else snprintf(fin,MAXTOKEN,"%s/%s/%s", workdir, indir, infile[i].fname);
      if (link(fin,infile[i].fname)) pfatal("cannot hardlink '%s'",fin);
      free(fin);
      
    } else {
    
      of = open(infile[i].fname,O_WRONLY|O_CREAT|O_TRUNC|O_EXCL,0600);
      if (of < 0) pfatal("unable to create '%s/%s'",outdir,infile[i].fname);

      if (infile[i].cur_len)
        if (write(of,infile[i].data,infile[i].cur_len) != infile[i].cur_len)
          fatal("short write to '%s/%s'",outdir,infile[i].fname);    
  
      close(of);
    
    }
    
    if (chdir(workdir)) fatal("unable to go back to work directory");

  }
  
  for (i=0;i<infcount;i++) {
    
    if (infile[i].cur_len) {
    
      /* Keep this non-fatal: we're trying to crash the client, so
         it might at some point become incapable of receiving our
	 data. */
    
      if (write(fd,infile[i].data,infile[i].cur_len) != infile[i].cur_len)
        debug("WARNING: Unable to complete write to output stream.\n");
	
    } else if (infile[i].asis) {
    
      /* Empty .keep file == sink client output. On output to WRONLY file or
         prematurely closed sockets, this will silently fail, which is 
	 precisely what we want. */
	 
      _u8 sink[MAXTOKEN];
      read(fd,sink,MAXTOKEN);
    }
    
  }
  
}


static _s32 lsock;
static _u16 lport;


/* Save-to-file handler */
static void commit_file(_u8* fn) {
  _s32 of;

  if (lport) { close(lsock); lport = 0; }
  
  /* The user might want to output to special devices, FIFOs and the like,
     and keep the file readable to other UIDs, so we skip unlink + O_EXCL
     and trust the environment is set up wisely. Keep-alive functionality of
     bunny-exec explicitly depends on this. */

  of = open(fn,O_WRONLY|O_CREAT|O_TRUNC,0644);
  if (of < 0) pfatal("unable to open '%s' for writing",fn);
  
  commit_data_fd(of);
  
  close(of);
  
}


/* Send to remote endpoint */
static void commit_connect(_u32 daddr,_u16 dport,_u8 udp) {
  _s32 csock;
  struct sockaddr_in sin;
  
  if (lport) { close(lsock); lport = 0; }
  
  csock = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0); 
  if (csock < 0) pfatal("socket() failed");
  
  sin.sin_family      = AF_INET;
  sin.sin_port        = dport;
  sin.sin_addr.s_addr = daddr;
  
try_connect_again:
  
  if (connect(csock, (struct sockaddr*)&sin, sizeof(sin))) {
  
    if (errno == ECONNREFUSED) {
      fd_set fds;
      FD_ZERO(&fds);
      FD_SET(0,&fds);

      if (select(1, &fds, 0, &fds, 0) < 0) 
        pfatal("select failed");

      if (FD_ISSET(0,&fds)) {
        debug("NOTE: connect() loop aborted by control command (something went wrong!)\n");
	close(csock);
        return;
      } else {
        sched_yield();
        goto try_connect_again;
      }

    }

    close(csock);
    debug("WARNING: Unable to initialize network connection to target.\n");
    return;
    
  }
  
  commit_data_fd(csock);
  
  close(csock);

}


/* Send to a locally accepted connection */
static void commit_tcp_accept(_u16 port) {
  _s32 csock, i;
  struct sockaddr_in sin;
  fd_set fds;
  
  /* The idea here is that as long as FLOW_TCP_ACCEPT is called for 
     the same port, we shouldn't dispose of the listener socket,
     as to minimize the risk of refused connections. */
  
  if (lport != port) {
    if (lport) close(lsock);
  
    lsock = socket(AF_INET, SOCK_STREAM, 0); 
    if (lsock < 0) pfatal("socket() failed");
  
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port        = port;
    
    if (bind(lsock, (struct sockaddr*)&sin, sizeof(sin)))
      pfatal("bind() failed");
      
    if (listen(lsock, 10)) pfatal("listen() failed");
    
    lport = port;
    
  }
  
  /* This shouldn't happen, but if the user configures some overly 
     aggressive timeouts, the traced process may get killed before
     it connects to read its input. To avoid a deadlock, we need to 
     bail out of an accept() wait if new control commands are available. */
  
  FD_ZERO(&fds);
  FD_SET(0,&fds);
  FD_SET(lsock,&fds);
  
  if (select(lsock + 1, &fds, 0, &fds, 0) < 0) 
    pfatal("select failed");

  if (FD_ISSET(0,&fds)) {
    debug("NOTE: accept() aborted by control command (something went wrong!)\n");
    return;
  }

  csock = accept(lsock, (struct sockaddr*)&sin, &i);
  if (csock < 0) pfatal("accept() failed");
  
  commit_data_fd(csock);
  close(csock);

}


/* Main command parsing loop */
static void process_commands(void) {
  struct bunny_flowreq f;

#define WRITE_RESPONSE(ret) do { \
    _u32 _rcode = (ret); \
    if (fwrite(&_rcode,sizeof(_u32),1,stdout) != 1)  \
      fatal("short write to manager"); \
    fflush(stdout); \
  } while (0)

  while (fread(&f,sizeof(struct bunny_flowreq),1,stdin) == 1) {
  
    switch (f.type) {
    
      case FLOW_RESCAN:
        reload_config();
	WRITE_RESPONSE(0);
	break;

      case FLOW_RESET:
        reset_state();
	WRITE_RESPONSE(0);
	break;
	
      case FLOW_GET_FUZZABLE:
	WRITE_RESPONSE(cur_fuzzable);
	break;
	
      case FLOW_BITFLIP:
        flip_bits(f.p1,f.p2);
	WRITE_RESPONSE(0);
	break;
	
      case FLOW_SETBYTE:
        set_byte(f.p1,f.p2);
	WRITE_RESPONSE(0);
        break;

      case FLOW_SETWORD:
        set_word(f.p1,f.p2);
	WRITE_RESPONSE(0);
        break;

      case FLOW_SETDWORD:
        set_dword(f.p1,f.p2);
	WRITE_RESPONSE(0);
        break;

      case FLOW_DELETE:
        remove_data(f.p1,f.p2);
	WRITE_RESPONSE(0);
        break;

      case FLOW_OVERWRITE:
        copy_data_ext(f.p1,f.p2,f.p3);
	WRITE_RESPONSE(0);
        break;

      case FLOW_INSERT:
        insert_data_ext(f.p1,f.p2,f.p3);
	WRITE_RESPONSE(0);
        break;

      case FLOW_SWAP:
        swap_data_ext(f.p1,f.p2,f.p3);
	WRITE_RESPONSE(0);
        break;
	
      case FLOW_SAVEFILE: {
          _u8* fn;
	  if (!f.p1 || f.p1 > MAXTOKEN) fatal("invalid FLOW_SAVEFILE");
	  fn = malloc(f.p1 + 1);
  	  if (!fn) fatal("out of memory");
	  if (fread(fn,f.p1,1,stdin) != 1) fatal("short filename read");
	  fn[f.p1] = 0;
	  commit_file(fn);
	  free(fn);
	}
	WRITE_RESPONSE(0);
	break;
	
      case FLOW_TCP_CONNECT: 
        /* We assume that p1 is already in net order */
	if (!f.p1 || f.p1 == 0xffffffff || !f.p2 || f.p2 > 65535)
	  fatal("invalid FLOW_TCP_CONNECT destination");

        /* Send response ahead of time, as the operation may block. */
  	WRITE_RESPONSE(0);
	commit_connect(f.p1,f.p2,0);
	break;

      case FLOW_TCP_ACCEPT:
	if (!f.p1 || f.p1 > 65535) 
	  fatal("invalid FLOW_TCP_ACCEPT destination");
        /* Send response ahead of time, as the operation may block. */
  	WRITE_RESPONSE(0);
	commit_tcp_accept(f.p1);
	break;

      case FLOW_UDP_SEND:
        /* We assume that p1 is already in net order */
	if (!f.p1 || f.p1 == 0xffffffff || !f.p2 || f.p2 > 65535)
	  fatal("invalid FLOW_UDP_SEND destination");
        /* Send response ahead of time, as the operation may block. */
  	WRITE_RESPONSE(0);
	commit_connect(f.p1,f.p2,1);
	break;

      default: 
        fatal("malformed cmd 0x%08x (%u,%u,%u)",f.type,f.p1,f.p2,f.p3);
  
    }
    
  }
  
}


/* Basic early sanity checks, to avoid delayed command-loop errors. */
static void validate_dirs(void) {
  struct stat s1, s2;

  if (!getcwd(workdir,MAXTOKEN)) pfatal("unable to get current dir");

  if (access(indir,R_OK | X_OK)  || stat(indir,&s1))  pfatal("unable to access '%s'",indir);
  if (access(outdir,W_OK | X_OK) || stat(outdir,&s2)) pfatal("unable to access '%s'",outdir);
  
  if (!S_ISDIR(s1.st_mode) || !S_ISDIR(s2.st_mode))
    fatal("parameter is not a directory");
    
  if (s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino)
    fatal("input and output dirs *really* have to be different");
}


static void exit_nicely(int sig) {
  debug("+++ bunny-flow terminated +++\n");
  exit(0);
}



int main(int argc,char** argv) {

  if (argc - 3)
    fatal("usage: %s input_dir/ output_dir/",argv[0]);
    
  indir  = argv[1];
  outdir = argv[2];

  signal(SIGPIPE,SIG_IGN);    
  signal(SIGTERM,exit_nicely);
  
  validate_dirs();
      
  debug("bunny-flow " VERSION " (" __DATE__ " " __TIME__ ") by <lcamtuf@google.com>\n");
  
  reload_config();
  process_commands();
  
  debug("Done - exiting gracefully.\n");

  return 0;
  
}

