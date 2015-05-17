/* Public interface to system wide RNG.
 *
 *    http://www.2uo.de/myths-about-urandom/
 * 
 * Copyright (c) 2013, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef mintls_random_h
#define mintls_random_h
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Read from /dev/urandom
void
mintls_random(
    unsigned char *     data,       // (O) Random bytes
    size_t const        len         // (I) Number of bytes
);


#ifdef __cplusplus
}
#endif

#endif /* tf_random_h */