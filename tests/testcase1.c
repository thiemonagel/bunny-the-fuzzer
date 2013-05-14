/*

   bunny - testcase #1
   -------------------

   Several tricky function / parameter detection scenarios for bunny-gcc.
   Yes, this will trigger plenty of compiler warnings; it's supposed to.

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


/* Not a function, but contains a function decl. */
struct whatever { 
  volatile int (*name1)(const int (*name2)(int,int));
};


/* Skipping structs is not enough - this is very much a function. */
struct { 
  volatile int (*name3)(const int (*name4)(int,int));
} myfunction(
  volatile int (*name5)(const int (*name6)(int,int)),
  struct { int name7, name8; } 
);
  

/* Function with perverted ANSI C style parameters - can we guess the name? */
static struct __attribute__((packed)) name9 {
  volatile int (*name10)(const int (*name11)(int,int));
  int (name12);
} (name13)(name_a,name_b,name_c)
  struct bark { int (*name14)( struct { int name15, name16; } param ); } *name_a;
  int name_b[10];
  int (name_c) __attribute__((pure));
  
  {
     printf("Goodbye.\n");
  }
  

/* A function returning pointer to a function. */
void* (*something(int p1, int p2))(int,int,int) {
  printf("How are you?\n");
}


/* Silly notation encountered in GMP or elsewhere... */
int (foo1)(int bar) {
  printf("Hello cruel world.\n");
  return (2+3+({2;}));
}

/* Function taking pointer to a function as a parameter. */
int foo2(int (*bar)(int a, int b, int c)) {
  return 7+2;
}


/* Insane variable/function decl mixing witnessed in some image processing library */
int value = 1, evilfunc();

main(void) {
  foo1(value);
  foo2(2);
  something(3,4);
  name13(5,6,7);
  usleep(100000);
  BunnySnoop 10;
}

