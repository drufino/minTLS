#ifndef tf_portability_h
#define tf_portability_h
/*
* Some simple routines to manage cross-platform compilation
*
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
*/

#ifdef _MSC_VER
#  include <stdlib.h>
#  define TF_INLINE __inline
#  define strncasecmp _strnicmp
#  define strcasecmp _stricmp
#  define VLA(type,name,size) type * name = (type *)alloca(sizeof(type) * size)
#  define byteswap16(x) _byteswap_ushort(x)
#  define byteswap32(x) _byteswap_ulong(x)
#  define byteswap64(x) _byteswap_uint64(x)
#  define TF_ALIGN __declspec(align(16))
#else
#  include <stdlib.h>
#  define TF_INLINE __inline__
#  define TF_ALIGN 
#  define byteswap64(x) __builtin_bswap64(x)
#  define byteswap32(x) __builtin_bswap32(x)
#  define byteswap16(x) __builtin_bswap16(x)
#  define VLA(type,name,size) type name[size]
#  define _aligned_malloc(sz,alignment) malloc(sz)
#  define _aligned_free(p) free(p)
#endif

#endif /* tf_portability_h */
