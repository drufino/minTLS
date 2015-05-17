/* IANA OID Registry
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef asn1_oid_registry_hpp
#define asn1_oid_registry_hpp

struct oid_registry_t {
    const char *oid_str;
    const char *oid_name;
};

extern struct oid_registry_t oid_registry[];
extern int    oid_registry_sz;

/* Look up the numeric IANA id from description
 */
const char *lookup_oid_from_name(const char *name);

#endif /* asn1_oid_registry_hpp */