/*

   bunny - gcc wrapper
   -------------------
   
   A drop-in replacement for gcc, meant to inject tracing hooks into the source after the
   preprocessing stage, but before compilation.

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

#include "types.h"
#include "config.h"
#include "debug.h"
#include "nlist.h"
#include "gcc-hook.h"
#include "message.h"

static struct naive_list 
  used_files,			/* C source files to be processed */
  preproc_params, 		/* Preprocessor parameter list */
  compile_params;		/* Compiler parameter list */

static _u32 mypid;

static _u8 gcc_mode;		/* -c, -E, -o, etc */
static _u8* output_file;	/* final -o parameter */

/*
   parse_params(argc,argv) - analyze gcc command-line parameters 
   
   Notes: gcc does not use getopt(), and implements a custom parser instead. It's pretty 
   inconsistent, too: '-g2' cannot be written as '-g 2', but '-xfoo' and '-x foo' are both 
   accepted. Long options are sometimes denoted with a single dash (-Xlinker), sometimes 
   with two dashes (--param). Parameter values are separated by ',', '=', or ' ', pretty much at 
   random. We need to mimick that insanity.
*/

static void parse_params(_u32 argc, _u8** argv) {
  _u32 pos = 1;
  
#define LANG_AUTO	0
#define LANG_C		1
#define LANG_OTHER	2
  
  _u8  lang = 0; /* LANG_* */
  
  if (argc <= 1) fatal("not enough parameters for gcc");
  
  /* Fill out argv[0] */
  ADD(preproc_params,"gcc");
  ADD(compile_params,"gcc");

#define c_alone(x) ((x) << 8)
#define c_any(x)   c_alone(x) ... (c_alone(x) + 254)
#define c_2(x,y)   ((x) << 8 | (y))

#define ADD_maysplit(list1,list2) do { \
    if (list1) ADD(preproc_params,argv[pos]); \
    if (list2) ADD(compile_params,argv[pos]); \
    if (!argv[pos][2]) { \
      if (++pos == argc) fatal("malformed %s option",argv[pos-1]); \
      if (list1) ADD(preproc_params,argv[pos]); \
      if (list2) ADD(compile_params,argv[pos]); \
    } \
  } while (0)

  while (pos < argc) {
  
    if (*argv[pos] == '-' && argv[pos][1]) {

      switch (c_2(argv[pos][1],argv[pos][2])) {
      
        /* We need special handlings for options that may be split into two
	   argvs, or need to be *not* passed to one of the processing stages. */

        /* BINARY OPTIONS TO KEEP OFF PREPROCESSOR COMMAND LINE */
	
	case c_alone('c'): /* stop at assembly      */
	case c_alone('E'): /* stop at preprocessing */
	case c_alone('S'): /* stop at compiling     */
	  gcc_mode = argv[pos][1];
	  ADD(compile_params,argv[pos]);
	  break;

        /* SPLITTABLE PARAMETRIC OPTIONS (FOR PREPROCESSOR ONLY) */

	case c_any  ('A'): /* -A assertion   */
	case c_any  ('D'): /* -D macro=val   */
	case c_any  ('I'): /* -I dir, -I-    */
	case c_any  ('U'): /* -U macro       */
	case c_2('i','d'): /* -idirafter     */
	case c_2('i','m'): /* -imacros       */
	case c_2('i','n'): /* -include       */
	case c_2('i','s'): /* -isyste,       */
	case c_2('i','w'): /* -iwithpref...  */
	case c_2('X','p'): /* -Xpreprocessor */
	  ADD_maysplit(1,0);
  	  break;	  

        /* SPLITTABLE PARAMETRIC OPTIONS (FOR COMPILER/LINKER ONLY) */

	case c_alone('b'): /* -b machine  */
	case c_any  ('l'): /* -l library  */
	case c_any  ('L'): /* -L libpath  */
	case c_alone('u'): /* -u symbol   */
	case c_any  ('V'): /* -V version  */
	case c_2('X','a'): /* -Xassembler */
	case c_2('X','l'): /* -Xlinker    */
	case c_2('-','p'): /* --param a=b */
	  ADD_maysplit(0,1);
  	  break;

	case c_any  ('o'): /* -o file     */
	  if (argv[pos][2]) output_file = argv[pos]+2; else output_file = argv[pos+1];
	  ADD_maysplit(0,1);
  	  break;


        /* SPLITTABLE PARAMETRIC OPTIONS (FOR ALL STAGES) */

	case c_any  ('B'): /* -B bindir */
	case c_2('a','u'): /* -aux-info */
	  ADD_maysplit(1,1);
  	  break;
	  
        /* It's important to track -x <foo> to determine the language of input files,
	   should they have unusual extensions. */

	case c_any  ('x'): {
	    _u8* lname = argv[pos] + 2;
            /* Handle splitting */	  
	    if (!*lname) {
	      if (++pos == argc) fatal("malformed -x option");
	      lname = argv[pos];
	    }
	    if (!strcmp(lname,"c")) lang = LANG_C; else
	    if (!strcmp(lname,"none")) lang = LANG_AUTO; 
	      else lang = LANG_OTHER;	    
	    ADD(compile_params,"-x");
	    ADD(compile_params, (lang == LANG_C) ? (_u8*)"cpp-output" : lname);
  	    break;
	  }  

	default: 		
	
	  /* Several compiler options won't play well with our solution: -fstrict-aliasing 
	     will generate warnings about our type-neutral parameter reading code; and -ansi
	     or -std= parameters may restrict our access to crucial gcc features we rely on, 
	     such as __attribute__ and typeof(). */

	  if (strcmp(argv[pos],"-fstrict-aliasing") && strcmp(argv[pos],"-ansi") &&
	      strncmp(argv[pos],"-std=",5)) {
	    ADD(preproc_params,argv[pos]);
	    ADD(compile_params,argv[pos]);
	  } else {
	    debug("[bunny] WARNING: '%s' is not supported, ignoring.\n",argv[pos]);
	  }
	  break;

      }

#undef c_alone
#undef c_any
#undef ADD_maysplit
      
    } else {
    
      _u8 tmp[128];
    
      /* Got what appears to be a filename. Decide how to proceed. */
      
      switch (lang) {
      
        case LANG_AUTO: 
	  if (!strcasecmp(argv[pos] + strlen(argv[pos]) - 2, ".c")) {
            sprintf(tmp,".bunny-%x-%u-f.i",mypid,used_files.c);
            ADD(used_files,argv[pos]);
            DYN_ADD(compile_params,tmp);
	  } else ADD(compile_params,argv[pos]);
	  break;
	  
	case LANG_C:
          sprintf(tmp,".bunny-%x-%u-f.i",mypid,used_files.c);
          ADD(used_files,argv[pos]);
          DYN_ADD(compile_params,tmp);
	  break;
	  
	case LANG_OTHER:
	  ADD(compile_params,argv[pos]);
	  
      }
	
    }
    
    pos++;
  
  }
  
  if (!used_files.c)
    debug("[bunny] No .c files to process spotted, will not install hooks.\n");
  
  /* Finishing touches: */
  
  ADD(compile_params,"-fno-strict-aliasing"); 	/* Explained earlier */
  ADD(preproc_params,"-xc");			/* Force C processing */
  ADD(preproc_params,"-E");			/* Preprocess only */
  ADD(preproc_params,"<file.c>");		/* Just a placeholder for input file */
  ADD(preproc_params,"-o");			
  ADD(preproc_params,"<file.i>"); 		/* Ditto, output. */
}


/* wait_execvp() - execute program in a new process, wait for return, handle errors. */

static void wait_execvp(_u8* path, _u8** argv) {
  _s32 pid, st;
  
  if (getenv("BUNNY_EXEC")) {    
    _u32 i = 0;
    debug(">> EXEC");
    while (argv[i]) debug(" %s",argv[i++]);
    debug("\n");
  }
  
  pid = fork();
  if (pid < 0) fatal("unable to spawn a process");
  
  if (!pid) {
    argv[0] = path;
    execvp(path,(char**)argv);
    pfatal("unable to invoke gcc (set $BUNNY_GCC)");
  } else {

    if (waitpid(pid,&st,0) != pid) pfatal("waitpid() fails?");
    
    if (WIFSIGNALED(st)) fatal("gcc died on signal %u",WTERMSIG(st));
    else if (WEXITSTATUS(st))
      fatal("gcc error (exit code %u)",WEXITSTATUS(st));
  }
  
}


/* precompile() - invoke precompiler, store output in a temporary file. */

static void precompile(void) {
  _u32 i;
  _u8 tmp[128], *gcc = getenv("BUNNY_GCC");
  
  if (!gcc) gcc = "/usr/bin/gcc";

  for (i=0;i<used_files.c;i++) {
    sprintf(tmp,".bunny-%x-%u.i",mypid,i);
    
    /* We "trust" gcc to safely create the output file. Perhaps not the best idea ever, but 
       then neither is running gcc in world-writable directories to begin with - no point
       in pretending we could fix it. */
    
    preproc_params.v[preproc_params.c-3] = used_files.v[i];
    preproc_params.v[preproc_params.c-1] = tmp;

    debug("[bunny] STAGE 1/3: Precompiling '%s'...\n",used_files.v[i]);
    wait_execvp(gcc,preproc_params.v);
    
  }
  
}



/* get_item() - try to isolate a single language token from the input file.
   See inline comments for more insight. */

static _u8* get_item(FILE* f) {
  _s32 c;
  static _u8 obuf[MAXTOKEN];
  _u32 olen = 0;
  _u8  qopen;
  
  if ((c = getc(f)) == EOF) return 0;

  /* Cluster whitespaces together */
  if (isspace(c)) {
    obuf[olen++] = c;
    while ((c=getc(f)) != EOF && isspace(c) && olen < MAXTOKEN - 1) obuf[olen++] = c;
    obuf[olen] = 0;
    if (olen != MAXTOKEN - 1 && c != EOF) ungetc(c,f);
    return obuf;
  }  

  /* Dump all text between "..." or '...' as a single token; watch for \, though */
  if (c == '"' || c == '\'') {
    _u8 escnext = 0;
    qopen = obuf[olen++] = c;
    while ((c=getc(f)) != EOF && (escnext || c != qopen) && olen < MAXTOKEN - 2) {
      if (!escnext) escnext = (c == '\\'); else escnext = 0;
      obuf[olen++] = c;
    }
    if (olen == MAXTOKEN - 2) fatal("string too long: '%.32s...'",obuf);
    if (c == EOF) fatal("unterminated string: '%.32s...'",obuf);
    obuf[olen++] = qopen;
    obuf[olen] = 0;

    return obuf;
  }
  
  /* Special handling for compiler directives (#) - copy whole line */
  if (c == '#') {
    obuf[olen++] = c;
    while ((c=getc(f)) != EOF && c != '\n' && olen < MAXTOKEN - 2) obuf[olen++] = c;
    if (olen == MAXTOKEN - 2) fatal("compiler directive too long: '%.32s...'",obuf);
    obuf[olen++] = '\n';
    obuf[olen] = 0;
    return obuf;
  }
  
  /* If found a run of [A-Za-z0-9_], consume it all. Everything else, return char-by-char. */
     
  while (olen < MAXTOKEN - 1) {
  
    if (!isalnum(c) && c != '_') {
      if (olen) ungetc(c,f); else obuf[olen++] = c;
      obuf[olen] = 0;
      return obuf;
    }
    
    obuf[olen++] = c;
    
    if ((c = getc(f)) == EOF) {
      obuf[olen] = 0;
      return obuf;
    }
    
  }
  
  fatal("line too long: '%.30s...'",obuf);

}


/* insert_hooks() - parse preprocessed file, locate functions, enumerate params, insert hooks.

   This truly is wicked - the goal is to insert possibly non-disruptive code to intercept
   function parameters as soon as possible (and this may look trivial until you consider that
   whole structs can be pushed on stack as parameters, local variables may shadow params,
   varargs need to be handled...); and to grab return codes with the same caveats.
   
 */

static void insert_hooks(void) {
  FILE *f, *o;
  _u32 fno;
  _u8  fname[128];
  
  /* A ridiculously complex state machine... */

  _u8  *tok,		/* Current input token     */
       *prev_name,	/* Previous alnum token    */
       *func_name,	/* Suspected function name */
       *prev_name1;	/* Kept as per keep_nest1  */
       
  _u32 code_nest,	/* Code nesting level - { ... } */
       expr_nest,	/* Expression nesting level - ( ... ) */
       prev_nest,	/* Previous element's expr nest level */
       prev_cnest,	/* Previous element's code nest level */
       param_nest,	/* Parameter parser nesting level */
       token_cnt,	/* Pointless stats */
       ret_nest,	/* Testing for void return (code + expr nest) */
       square_nest,	/* [...] nest level */
       hook_cnt;	/* Ditto */
       
  _u8  get_params,	/* Inside a parameter list? */
       keep_nest1,	/* Grab first token at expr nest param_nest + 1 */
       params_ok,	/* Parameters collected OK */
       got_struct,	/* { } may refer to struct/enum/union */
       do_second,	/* Second chance parameter acquisition */
       ret_void,        /* return is void? */
       in_func,		/* in function? */
       ignore_now,	/* ignoring func params until ; */
       check_decl;	/* Try to tell decl from def */
       
  struct naive_list params = { 0, 0 };
  
  for (fno=0;fno<used_files.c;fno++) {
    _s32 ofn;
    _u8  *curfn;
    
    code_nest   = 0;
    expr_nest   = 0;
    prev_name   = 0;
    func_name   = 0;
    get_params  = 0;
    params_ok   = 0;
    keep_nest1  = 0;
    prev_nest   = 0;
    prev_cnest  = 0;
    prev_name1  = 0;
    param_nest  = 0;
    check_decl  = 0; 
    token_cnt   = 0;
    hook_cnt    = 0;
    got_struct  = 0;
    do_second   = 0;
    ret_void    = 0;
    ret_nest    = 0;
    in_func     = 0;
    ignore_now  = 0;
    square_nest = 0;
    
    curfn = used_files.v[fno];

    /* Open input and output files... */  
    sprintf(fname,".bunny-%x-%u.i",mypid,fno);
    f = fopen(fname,"r");
    if (!f) pfatal("unable to read file %s",fname);
    if (!getenv("BUNNY_KEEPTEMP")) unlink(fname);
    
    sprintf(fname,".bunny-%x-%u-f.i",mypid,fno);
    unlink(fname);
    ofn = open(fname,O_WRONLY|O_CREAT|O_EXCL,0600);
    if (ofn < 0) pfatal("unable to create temp file %s",fname);
    if (!(o = fdopen(ofn,"w"))) fatal("unable to create FILE object");

#define outf(x...) fprintf(o,x)
    
#define OUTPUT_RETURN_VOID() \
    outf(" do { __bunny_send_msg(0x%08x, 0, 0, 0); return; } while (0) ", MESSAGE_LEAVE)

#define OUTPUT_RETURN_FINAL() \
    outf("  __bunny_send_msg(0x%08x, 0, 0, 0); ", MESSAGE_LEAVE)

#define OUTPUT_RETURN_PROLOGUE() \
    outf(" do { __bunny_ret_t __bunny_ret = ( ")

#define OUTPUT_RETURN_EPILOGUE() \
    outf(" ); __bunny_send_msg(0x%08x, *(unsigned int*)&__bunny_ret, 0, 0); " \
         "return __bunny_ret; } while (0) ", MESSAGE_LEAVE)    

#if 0
#  define DEBUGF(x...) printf(x)
#else
#  define DEBUGF(x...) do {} while (0)
#endif 

    /* Store our hook code at the very beginning the output file. */
    outf("# 1 \"<bunny internal code>\"\n\n%s\n\n",bunny_hook_code);
    
    while ((tok=get_item(f))) {
    
      token_cnt++;
     
      DEBUGF(">>> NEW TOKEN [%s]\n",tok);
      
      /* This is a special case - don't look inside */
      if (!strcmp(tok,"__attribute__") || !strcmp(tok,"__asm__")) {
        _s32 iexp_nest = expr_nest;
	
	outf("%s",tok);
	
        while (iexp_nest >= 0 && (tok=get_item(f))) {
          token_cnt++;
	  
	  switch (tok[0]) {
	    case '(': outf("%s", tok); expr_nest++; break;
	    case ')': outf("%s", tok);
	              if (!expr_nest) 
		        fatal("nesting error inside __attribute__ / __asm__ in '%s'",curfn);
	              if (--expr_nest == iexp_nest) iexp_nest = -1; 
		      break;
	    default:  outf("%s", tok);
	  }
	  
	}
	if (!tok) fatal("unterminated __attribute__ in '%s'",used_files.v[fno]);
	continue;
      }

      /* Another special case is our "BunnySnoop" directive */
      if (!strcmp(tok,"BunnySnoop")) {
        if (!code_nest) fatal("stray BunnySnoop block in '%s'",used_files.v[fno]);

        outf("do { volatile char __attribute__((unused)) __dummy = "
             "__bunny_send_msg(0x%08x,(unsigned int)(",
             MESSAGE_SPOT);

        while ((tok = get_item(f))) {
          token_cnt++;
          if (tok[0] == ';') break;
  	  outf("%s",tok);
        }

        if (!tok) fatal("unterminated BunnySnoop block in '%s'",curfn);

        outf("),0,0); } while (0);\n");
        hook_cnt++;

        continue;

      }

      /* And a yet another one... */
      if (!strcmp(tok,"BunnySkip")) {
        if (!code_nest && !expr_nest) {
          DEBUGF("<<BunnySkip detected, bailing out>>\n");
          DYN_FREE(params);
          free(func_name);
          free(prev_name);
          prev_name  = 0;
          func_name  = 0;
          params_ok  = 0;
          check_decl = 0;
          ignore_now = 1;
        } else fatal("misplaced BunnySkip statement in '%s'",curfn);
        continue;
      }

      switch (tolower(tok[0])) {
      
        case '(':

	  if (ret_void) {
	    OUTPUT_RETURN_PROLOGUE();
	    ret_void = 0;
	  }

	  expr_nest++;
	  
	  /* This might be a function param list */
	  if (!code_nest && !get_params && !prev_cnest && !ignore_now) {
	  
	    if (params_ok && !do_second && params.c == 1) {
	      DEBUGF("<<<second chance (name set to %s)>>>\n",params.v[0]);
  	      free(func_name);
	      free(prev_name);
	      func_name  = 0;
	      prev_name  = strdup(params.v[0]);
	      if (!prev_name) fatal("out of memory");
	      DYN_FREE(params);
	      params_ok  = 0;
	      keep_nest1 = 0;
	      do_second  = 1;
	      check_decl = 1;
	    }
	  
	    if (!params_ok && prev_name) {
	      DEBUGF("<<starting to collect params>>\n");
  	      func_name = strdup(prev_name);
	      if (!func_name) fatal("out of memory");
	      free(prev_name);
	      prev_name  = 0;
	      get_params = 1;
	      param_nest = expr_nest;
	      keep_nest1 = 1;
	    }
          }	    
	  
	  outf("%s",tok);
          break;
	  
	case '=':
	  /* Disregard anything that seemed like a function if = is encountered */
	  if (!code_nest && !expr_nest) {
	    DEBUGF("<<assignment detected, bailing out>>\n");
	    DYN_FREE(params);
	    free(func_name);
	    free(prev_name);
	    prev_name  = 0;
	    func_name  = 0;
	    params_ok  = 0;
	    check_decl = 0;
	    ignore_now = 1;
	  }

	  
	case ',':

          if (!code_nest && !expr_nest) goto handle_as_colon;
          /* Fall through */

	case ')':
	
	  /* We might have a parameter! Write it down. */
	  if (get_params && !code_nest && expr_nest == param_nest) {
            if (prev_nest == param_nest) {
	      DEBUGF("<<storing prev_name as param>>\n");
	      if (prev_name && strcmp(prev_name,"void")) DYN_ADD(params,prev_name);
	    } else {
	      DEBUGF("<<storing prev_name1 as param>>\n");
	      if (prev_name1) DYN_ADD(params,prev_name1);
	    }
	    
	    /* Avoid unintentional reuse of prev_name */
	    if (prev_name) free(prev_name);
	    if (prev_name1) free(prev_name1);
	    prev_name = prev_name1 = 0;
	    
	    /* Finalize parameter list... */
	    if (tok[0] == ')') {
	      DEBUGF("<<finalizing param list>>\n");
	      keep_nest1 = 0;
	      get_params = 0;
	      params_ok  = 1;
	      check_decl = 1;
	    } else keep_nest1 = 1;
	    
	  }

          if (tok[0] == ')') {	  
  	    if (!expr_nest) fatal("')' nesting level error in '%s'", curfn);
	    expr_nest--;
	  } 
	  
	  outf("%s",tok);
          break;	  
	
	case '[':

	  expr_nest++;
	  square_nest++;
	  outf("%s",tok);
          break;	  
	
	case ']':

	  if (!expr_nest) fatal("']' nesting level error in '%s'", curfn);
	  expr_nest--;
	  square_nest--;
	  outf("%s",tok);
          break;	  
	  
	case '*':

	  if (ret_void) {
	    OUTPUT_RETURN_PROLOGUE();
	    ret_void = 0;
	  }
	
	  /* What we thought is a parameter list contains a function name */
	  if (expr_nest == 1 && !code_nest && get_params == 1 && !do_second) {
	    DEBUGF("<<param list reclassified as func name>>\n");
	    free(func_name);
	    func_name  = 0;
	    get_params = 0;
	    keep_nest1 = 0;
	    do_second  = 1;
	  }
	  
	  outf("%s",tok);
	  break;
	  
	case ';':

handle_as_colon:
	
	  if (!code_nest) { got_struct = 0; do_second = 0; ignore_now = 0; }

	  if (ret_nest && code_nest + expr_nest == ret_nest) {
	    if (ret_void) OUTPUT_RETURN_VOID(); else OUTPUT_RETURN_EPILOGUE();
	    ret_void = 0;
	    ret_nest = 0;
	  }
	
	  /* So, we indeed have a declaration and nothing more. */
	  if (check_decl && !code_nest && !expr_nest) {
	    DEBUGF("<<no function body detected, bailing out>>\n");
	    DYN_FREE(params);
	    free(func_name);
	    func_name  = 0;
	    params_ok  = 0;
	    check_decl = 0;
	  }

	  outf("%s",tok);
	  break;
	  
	case '{':

	  outf("%s",tok);
	
	  /* We're set for a real function, eh? */
	  if (!code_nest && !expr_nest && params_ok && !got_struct) {
	    _u32 i;
	    
	    DEBUGF(">>> NEW FUNCTION '%s'\n", func_name);
	    
	    for (i=0;i<params.c;i++)
	      DEBUGF(">>> parameter '%s'\n",params.v[i]);
	      
	    /* We want to execute our code at the very beginning of the function. 
	       This is possible with a nifty abuse of variable initialization. */
	  
            outf(" volatile char __attribute__((unused)) __dummy_i = "
                 "__bunny_send_msg(0x%08x,%u,\"%s\",%u); ", MESSAGE_ENTER,
                params.c, func_name, strlen(func_name));
							
            for (i=0;i<params.c;i++) 
              outf(" volatile char __attribute__((unused)) __dummy_%03u = "
                   "__bunny_send_msg(0x%08x,*(unsigned int*)&(%s),0,0); ", i,
                   MESSAGE_PARAM, params.v[i]);
		
	    /* We need to know what our function returns to intercept return values
	       at a later date. */
	       														  
            outf(" typedef typeof(%s(",func_name);
            for (i=0;i<params.c;i++) outf("%s%s", i?", ":"", params.v[i]);
            outf(")) __bunny_ret_t;");

            /* Count enter, return, params */
            hook_cnt += 2 + params.c;
			    
	    DYN_FREE(params);
	    free(func_name);
	    func_name = 0;
	    params_ok = 0;
	    
	    in_func   = 1;

	  }
	  
	  code_nest++;
          break;	  

	case '}':
	
	  if (!code_nest) fatal("code nesting level error in '%s'", curfn);
	  code_nest--;	  
	  
	  if (!code_nest && in_func) {
            OUTPUT_RETURN_FINAL();
	    do_second = 0;
	    in_func   = 0;
	  }

          outf("%s",tok);
	  
          break;	  
	  
	/* Word token */
	case 'a' ... 'z':
	case '_':

	  if (get_params == 1) get_params = 2;
	  
	  if (!square_nest) {
  	    if (prev_name) free(prev_name);
	    prev_name  = strdup(tok);
	    if (!prev_name) fatal("out of memory");
	    prev_nest  = expr_nest;
	    prev_cnest = code_nest;
	  }
	  
	  if (keep_nest1 && param_nest + 1 == expr_nest && !square_nest) {
	    DEBUGF("<<storing as keep_nest1>>\n");
	    prev_name1 = strdup(tok);
	    if (!prev_name1) fatal("out of memory");
	    keep_nest1 = 0;
	  }

          /* We got something other than ';' and '__attribute__' following a parameter
	     list; this is likely a definition, not a declaration. */
	     
	  if (!expr_nest && !square_nest) check_decl = 0;
	  
          if (!code_nest && params_ok && (!strcmp(tok,"struct") || !strcmp(tok,"enum") ||
	      !strcmp(tok,"union"))) got_struct = 1;
          	  
	  /* Register parameters are incompatible with our parameter grabbing code,
	     and getting rid of them has pretty much no effect for most uses. */
	  if (!code_nest && !strcmp(tok,"register")) break;
	  
	  /* We need to intercept 'return' and report the value. */
	  if (!strcmp(tok,"return") && in_func) { ret_nest = code_nest + expr_nest; ret_void = 1; break; }
	  
	  /* Fall through */
	
	/* Whitespaces, numbers, operators, text, compiler directives... */
	case '0' ... '9':
	default:

	  if (ret_void && !isspace(tok[0])) {
	    OUTPUT_RETURN_PROLOGUE();
	    ret_void = 0;
	  }
	
	  outf("%s",tok);
	  break;
	  	  
      }

      DEBUGF(">>> prevn='%s' fn='%s' prevn1='%s' cn=%d en=%d prevn=%d parn=%d\n    getp%d keep%d pok%d cdecl%d sec%d ig%d\n",
        prev_name, func_name, prev_name1, code_nest, expr_nest, prev_nest, param_nest,
	get_params, keep_nest1, params_ok, check_decl,do_second, ignore_now);

#undef DEBUGF
#undef outf
#undef OUTPUT_RETURN_VOID
#undef OUTPUT_RETURN_PROLOGUE
#undef OUTPUT_RETURN_EPILOGUE
  
    }    
    
    if (prev_name) free(prev_name);
    if (func_name) free(func_name);
    DYN_FREE(params);
    
    if (code_nest || expr_nest) 
      fatal("EOF at nest level %u/%u in '%s'", code_nest, expr_nest, used_files.v[fno]);
      
    fclose(f);
    fclose(o);
    
    debug("[bunny] STAGE 2/3: Injected %u hooks into '%s' (%u tokens).\n",hook_cnt,
          used_files.v[fno],token_cnt);
    
  }
  
  /* Free at last! */
    
}


/* compile() - consolidate, compile and link all the files. */

static void compile(void) { 
  _u8 *gcc = getenv("BUNNY_GCC");
  _u32 i;
  _u8 fname[128];
    
  if (!gcc) gcc = "/usr/bin/gcc";
  
  switch (gcc_mode) {
  
    case 'c':
      if (output_file) {
        debug("[bunny] STAGE 3/3: Compiling binary to '%s'...\n",output_file);
      } else {      
        debug("[bunny] STAGE 3/3: Compiling binary to default .o file(s)...\n");
      }
      break;
         
    case 'S':
      if (output_file) {
        debug("[bunny] STAGE 3/3: Compiling assembly code to '%s'...\n",output_file);
      } else {
        debug("[bunny] STAGE 3/3: Compiling assembly code to default .s file(s)...\n");
      }
      break;
      
    default:
      if (output_file) {
        debug("[bunny] STAGE 3/3: Compiling and linking executable to '%s'...\n",output_file);
      } else {
        debug("[bunny] STAGE 3/3: Compiling and linking executable to default location...\n");
      }
      break;
      
  }
  
  wait_execvp(gcc,compile_params.v);
  
  /* Us succeed? That's unpossible. */

  for (i=0;i<used_files.c;i++) {
    sprintf(fname,".bunny-%x-%u-f.i",mypid,i);
    if (!getenv("BUNNY_KEEPTEMP")) unlink(fname);
  }    
  
  /* We have to remove .o files to their ultimate destinations if no 'o' flag was found
     (if one was used, rename() will fail silently). */
  if (gcc_mode == 'c' || gcc_mode == 'S') 
    for (i=0;i<used_files.c;i++) {
      _u8 tmp[MAXTOKEN + 2], *per;
      if (gcc_mode == 'c') sprintf(fname,".bunny-%x-%u-f.o",mypid,i);
        else sprintf(fname,".bunny-%x-%u-f.s",mypid,i);
      
      tmp[MAXTOKEN-1] = 0;
      per = strrchr(used_files.v[i],'/');
      if (!per) per = used_files.v[i]; else per++;
      strncpy(tmp,per,MAXTOKEN-1);
      
      per = strrchr(tmp,'.');
      if (per) *per = 0;
      
      if (gcc_mode == 'c') strcat(tmp,".o"); else strcat(tmp,".s");
      
      rename(fname,tmp);
      
    }    
  
}


/* dump_code() - output preprocessed code (-E option) */
static void dump_code(void) {
  _u32 fno;

  if (output_file) {
    debug("[bunny] STAGE 3/3: Dumping modified source to '%s'...\n",output_file);
  } else {      
    debug("[bunny] STAGE 3/3: Dumping modified source to stdout...\n");
  }
  
  for (fno=0;fno<used_files.c;fno++) {
    _u8  cbuf[1024], fname[128];
    _s32 fin, fout, i;
    
    sprintf(fname,".bunny-%x-%u-f.i",mypid,fno);
    
    if (output_file) {
       unlink(output_file);
       fout = open(output_file, O_CREAT | O_EXCL | O_WRONLY, 0600);
       if (fout < 0) pfatal("unable to create '%s'",output_file);
    } else fout = 1;
    
    fin = open(fname, O_RDONLY);
    if (!fin) pfatal("unable to read '%s'",fname);
    
    while ((i=read(fin,cbuf,sizeof(cbuf))) > 0) write(fout,cbuf,i);
    
    close(fin);
    if (output_file) close(fout);
    
    if (!getenv("BUNNY_KEEPTEMP")) unlink(fname);
  }      
  
  
}


int main(int argc,char** argv) {

  mypid = getpid();
  
  debug("[bunny] bunny-gcc " VERSION " (" __DATE__ " " __TIME__ ") by <lcamtuf@google.com>\n");

  parse_params((_u32)argc,(_u8**)argv);
  precompile();
  insert_hooks();
  
  /* Common sense would suggest that calling gcc -E <file.i> -o <file.i> would simply copy
     input to output. No dice. */
  
  if (gcc_mode == 'E') dump_code(); else compile();

  exit(0);
  
}

