/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_USDT_H
#define OSSL_USDT_H
#pragma once

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_USDT
#include <stdint.h>
#include <sys/sdt.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct ossl_usdt_data_st {
    const char *key;
    const void *value;
    unsigned long value_size;
} OSSL_USDT_DATA;

#define OSSL_USDT_STRING(s) s, (unsigned long)-1
#define OSSL_USDT_WORD(w) (void *)(intptr_t)w, (unsigned long)-2
#define OSSL_USDT_BLOB(b, s) b, s

/*
 * Emits a context event with the given |name|.
 */
#define OSSL_USDT_new_context(context, name)                                    \
    do {                                                                        \
        OSSL_USDT_DATA data_[] = { { "name", OSSL_USDT_STRING(name) } };        \
        DTRACE_PROBE4(crypto_auditing, new_context_with_data, context, context, \
            data_, sizeof(data_) / sizeof(data_[0]));                           \
    } while (0)

/*
 * Combines OSSL_USDT_new_context() followed by OSSL_USDT_data() as a
 * single probe.
 */
#define OSSL_USDT_new_context_with_data(context, name, ...)                           \
    do {                                                                              \
        OSSL_USDT_DATA data_[] = { { "name", OSSL_USDT_STRING(name) }, __VA_ARGS__ }; \
        DTRACE_PROBE4(crypto_auditing, new_context_with_data, context, context,       \
            data_, sizeof(data_) / sizeof(data_[0]));                                 \
    } while (0)

/*
 * Emits multiple data events at once as a variadic array of
 * OSSL_USDT_DATA in the current event context.
 */
#define OSSL_USDT_data(context, ...)                                                            \
    do {                                                                                        \
        OSSL_USDT_DATA data_[] = { __VA_ARGS__ };                                               \
        DTRACE_PROBE3(crypto_auditing, data, context, data_, sizeof(data_) / sizeof(data_[0])); \
    } while (0)

/*
 * Asserts an explicit parent-child relationship of context.
 */
#define OSSL_USDT_new_child(parent_context, context) \
    DTRACE_PROBE2(crypto_auditing, new_context, context, parent_context)

/*
 * Declares that |context| is retired and its value may be reused for
 * other purposes.  This should be emitted when an object used as a
 * context is freed, before the memory can be recycled for another
 * object.
 */
#define OSSL_USDT_release_context(context) \
    DTRACE_PROBE1(crypto_auditing, release_context, context)

#ifdef __cplusplus
}
#endif

#else

#define OSSL_USDT_STRING(s)
#define OSSL_USDT_WORD(w)
#define OSSL_USDT_BLOB(b, s)

#define OSSL_USDT_new_context(context, name)
#if defined(_MSC_VER) && _MSC_VER < 1400
/*
 * Old MSVC (VC6) has no variadic macros.  Every caller passes exactly one
 * { key, value } initializer, which the preprocessor splits into two
 * arguments at the top-level comma, so fixed-arity macros are enough.
 */
#define OSSL_USDT_new_context_with_data(context, name, key, value)
#define OSSL_USDT_data(context, key, value)
#else
#define OSSL_USDT_new_context_with_data(context, name, ...)
#define OSSL_USDT_data(context, ...)
#endif
#define OSSL_USDT_new_child(parent_context, context)
#define OSSL_USDT_release_context(context)

#endif
#endif /* OSSL_USDT_H */
