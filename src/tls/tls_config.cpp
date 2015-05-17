/* TLS Session Config
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "tls/tls_config.hpp"

TLSConfig::TLSConfig()
{
    trust_type = TrustTypes::FULL;
}