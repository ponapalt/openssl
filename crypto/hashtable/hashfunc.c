/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 */

#include "internal/hashfunc.h"

ossl_unused unsigned __int64 ossl_fnv1a_hash(uint8_t *key, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325Ui64;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= 0x00000100000001B3Ui64;
    }
    return hash;
}
