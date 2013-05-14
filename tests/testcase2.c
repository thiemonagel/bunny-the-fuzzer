/*

   bunny - testcase #2
   -------------------

   A hard-to-fuzz scenario for bunny-main (compile with bunny-gcc).

   The only input that crashes this is \x00\x10\x20\x30; a blind fuzzer
   would take forever to get to the fault condition.

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
#include <sys/time.h>

char c[3];

void do_nothing(time_t t) { }


void dostuff3(int param) {
  char* x = (char*)0x5;
  if (param == 0x30) *x = 5;
}

void dostuff2(void) {
  if (c[2] == 0x20) dostuff3(c[3]);
}


void dostuff1(void) {
  if (c[1] == 0x10) dostuff2();
}


int main(int argc,char** argv) {

  do_nothing(time(0));

  read(0,c,4);

  if (c[0] == 0x00) dostuff1();

}


