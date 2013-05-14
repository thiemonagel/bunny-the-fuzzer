/*

   bunny - naive dynamic list implementation
   -----------------------------------------

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

#ifndef _HAVE_NLIST_H
#define _HAVE_NLIST_H

#include "types.h"

struct naive_list { _u8** v; _u32 c; };

#define ADD(list,val) do { \
    struct naive_list* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v = realloc(__list->v,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      if (!__list->v) fatal("out of memory"); \
    } \
    __list->v[__list->c++] = (val); \
    __list->v[__list->c] = 0; \
  } while (0)
  
#define DYN_ADD(list,val) do { \
    _u8* _s = strdup(val); \
    if (!_s) fatal("out of memory"); \
    ADD((list),_s); \
  } while (0)

#define FREE(list) do { \
    struct naive_list* __list = &(list); \
    if (__list->v) free(__list->v); \
    __list->v = 0; \
    __list->c = 0; \
  } while (0);

#define DYN_FREE(list) do { \
    _u32 _i; \
    struct naive_list* __list = &(list); \
    for (_i=0;_i<__list->c;_i++) \
      if (__list->v[_i]) free(__list->v[_i]); \
    if (__list->v) free(__list->v); \
    __list->v = 0; \
    __list->c = 0; \
  } while (0);


struct naive_list_int { _u32* v; _u32 c; };

#define ADDINT(list,val) do { \
    struct naive_list_int* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v = realloc(__list->v,(1 + ALLOC_CHUNK + __list->c) * sizeof(_u32)); \
      if (!__list->v) fatal("out of memory"); \
    } \
    __list->v[__list->c++] = (val); \
  } while (0)

#define FREEINT(list) do { \
    struct naive_list_int* __list = &(list); \
    if (__list->v) free(__list->v); \
    __list->v = 0; \
    __list->c = 0; \
  } while (0);


struct naive_list_int64 { _u64* v; _u32 c; };

#define ADDINT64(list,val) do { \
    struct naive_list_int64* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v = realloc(__list->v,(1 + ALLOC_CHUNK + __list->c) * sizeof(_u64)); \
      if (!__list->v) fatal("out of memory"); \
    } \
    __list->v[__list->c++] = (val); \
  } while (0)

#define FREEINT64(list) do { \
    struct naive_list_int64* __list = &(list); \
    if (__list->v) free(__list->v); \
    __list->v = 0; \
    __list->c = 0; \
  } while (0);


struct naive_list_ptr { void** v; _u32 c; };

#define ADDPTR(list,val) do { \
    struct naive_list_ptr* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v = realloc(__list->v,(1 + ALLOC_CHUNK + __list->c) * sizeof(void*)); \
      if (!__list->v) fatal("out of memory"); \
    } \
    __list->v[__list->c++] = (void*)(val); \
  } while (0)

#define FREEPTR(list) do { \
    struct naive_list_ptr* __list = &(list); \
    if (__list->v) free(__list->v); \
    __list->v = 0; \
    __list->c = 0; \
  } while (0);


struct naive_list_int2 { _u32 *v1, *v2; _u32 c; };

#define ADDINT2(list,val1,val2) do { \
    struct naive_list_int2* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v1 = realloc(__list->v1,(1 + ALLOC_CHUNK + __list->c) * sizeof(_u32)); \
      __list->v2 = realloc(__list->v2,(1 + ALLOC_CHUNK + __list->c) * sizeof(_u32)); \
      if (!__list->v1 || !__list->v2) fatal("out of memory"); \
    } \
    __list->v1[__list->c] = (val1); \
    __list->v2[__list->c++] = (val2); \
  } while (0)

#define FREEINT2(list) do { \
    struct naive_list_int2* __list = &(list); \
    if (__list->v1) free(__list->v1); \
    if (__list->v2) free(__list->v2); \
    __list->v1 = __list->v2 = 0; \
    __list->c = 0; \
  } while (0);


#endif /* ! _HAVE_NLIST_H */
