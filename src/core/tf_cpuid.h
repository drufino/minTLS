/* Some helper functions for x86 CPUID instructions
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_cpuid_h
#define tf_cpuid_h
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// 1 if true, 0 otherwise
int cpu_supports_ssse3();

// 1 if supports AES-NI, 0 otherwise
int cpu_supports_aesni();

#ifdef __cplusplus
}
#endif

#endif