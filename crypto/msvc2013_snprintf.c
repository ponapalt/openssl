/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * C99 snprintf and vsnprintf emulation for MSVC versions earlier than
 * Visual Studio 2015 (_MSC_VER < 1900).  Those compilers ship _snprintf
 * and _vsnprintf with non-C99 semantics (return -1 on truncation, no
 * guaranteed NUL termination) and do not provide the standard names at
 * all.  This file supplies the missing C99 names.
 *
 * This file is only compiled when the configured target is one of the
 * Windows MSVC 2013 compatibility variants; on every other platform
 * the standard library already provides these symbols.
 *
 * IMPORTANT: This translation unit MUST define snprintf and vsnprintf
 * and nothing else.  This single file is compiled directly into libcrypto,
 * libssl, and the apps; each references it from its own build.info rather
 * than keeping a copy.  Because each definition lives in its own .obj, the
 * linker's archive-search rule ensures only one copy is pulled into any
 * final binary.  Defining any additional symbol here would risk pulling
 * multiple copies and producing a duplicate-symbol link error.
 */

#if defined(_MSC_VER) && _MSC_VER < 1900

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "internal/numbers.h"
#include <openssl/crypto.h>

/*
 * Compatibility with the older toolchains this file exists for.  Note that
 * <stdint.h> must not be included here: it does not exist before VS2010, so
 * SIZE_MAX comes from "internal/numbers.h" above.
 */
#if defined(_MSC_VER)
# if _MSC_VER < 1800
   /* va_copy is not available in MSVC before VS2013 */
#  ifndef va_copy
#   define va_copy(dst, src) ((dst) = (src))
#  endif
# endif
# if _MSC_VER < 1400
   /* _TRUNCATE is not available in MSVC before VS2005 */
#  ifndef _TRUNCATE
#   define _TRUNCATE ((size_t)-1)
#  endif
# endif
#endif

/*
 * _MSC_VER described here:
 * https://learn.microsoft.com/en-us/cpp/overview/compiler-versions?view=msvc-170
 *
 * Beginning with the UCRT in Visual Studio 2015 and Windows 10, snprintf is no
 * longer identical to _snprintf. The snprintf behavior is now C99 standard
 * conformant. The difference is that if you run out of buffer, snprintf
 * null-terminates the end of the buffer and returns the number of characters
 * that would have been required whereas _snprintf doesn't null-terminate the
 * buffer and returns -1. Also, snprintf() includes one more character in the
 * output because it doesn't null-terminate the buffer.
 * [ https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snprintf-snprintf-snprintf-l-snwprintf-snwprintf-l?view=msvc-170#remarks
 *
 * for older MSVC (older than 2015) we can use _vscprintf() and _vsnprintf()
 * as suggested here:
 * https://stackoverflow.com/questions/2915672/snprintf-and-visual-studio-2010
 *
 */
static int msvc_translate_printf_format(const char *format, const char **out,
    char **tmp)
{
    /* Valid printf conversion specifiers, grouped by category: signed
     * integers (d i), unsigned (o u x X), floating-point (f F e E g G a A),
     * misc (c s p n) and MSVC-specific (S Z C). */
    static const char conv[] = "diouxXfFeEgGaAcspnSZC";
    const char *p = format;
    char *dst = NULL, *q = NULL;

    /*
     * The pre-2015 CRTs do not understand the C99 length modifiers, and the
     * oldest ones (VC6 and friends) do not understand ll or hh either.
     * Translate:
     *
     *   z, t -> I    (both are pointer-sized on Windows)
     *   j    -> I64  (intmax_t is 64 bits)
     *   ll   -> I64
     *   hh   -> nothing (the argument is promoted to int anyway, so the bare
     *                    conversion specifier does the right thing)
     *
     * Every input character expands to at most three output characters
     * (j -> I64, ll -> I64), so 3 * length is a safe bound for the buffer.
     *
     * This is done in a single pass: nothing is allocated until the first
     * modifier is seen, so formats that need no translation return the
     * original string untouched. EMIT_CHAR() appends a character to the
     * output once the buffer exists; before that it is a no-op. ALLOC_BUF()
     * creates the buffer and flushes everything preceding the modifier that
     * starts at m.
     */
#define EMIT_CHAR(c)     \
    do {                 \
        if (dst != NULL) \
            *q++ = (c);  \
    } while (0)

#define ALLOC_BUF(m)                                            \
    do {                                                        \
        if (dst == NULL) {                                      \
            size_t len = strlen(format);                        \
                                                                \
            if (len > (SIZE_MAX - 1) / 3) /* static analysis */  \
                return 0;                                       \
            dst = (char *)OPENSSL_malloc(3 * len + 1);          \
            if (dst == NULL)                                    \
                return 0;                                       \
            q = dst;                                            \
            memcpy(q, format, (size_t)((m) - format));          \
            q += (m) - format;                                  \
        }                                                       \
    } while (0)

    *out = format;
    *tmp = NULL;

    while (*p != '\0') {
        if (*p != '%') { /* literal character */
            EMIT_CHAR(*p);
            p++;
            continue;
        }
        p++; /* consume '%' */
        if (*p == '%') { /* literal "%%" */
            EMIT_CHAR('%');
            EMIT_CHAR('%');
            p++;
            continue;
        }
        EMIT_CHAR('%');
        while (*p != '\0' && strchr(conv, *p) == NULL) {
            const char *m = p;
            char c = *p++;

            if (c == 'l' && *p == 'l') { /* ll -> I64 */
                p++;
                ALLOC_BUF(m);
                EMIT_CHAR('I');
                EMIT_CHAR('6');
                EMIT_CHAR('4');
                continue;
            }
            if (c == 'h' && *p == 'h') { /* hh -> nothing */
                p++;
                ALLOC_BUF(m);
                continue;
            }
            if (c == 'z' || c == 't' || c == 'j') {
                ALLOC_BUF(m);
                EMIT_CHAR('I');
                if (c == 'j') {
                    EMIT_CHAR('6');
                    EMIT_CHAR('4');
                }
                continue;
            }
            EMIT_CHAR(c); /* verbatim */
        }
        if (*p != '\0') { /* copy the conversion specifier */
            EMIT_CHAR(*p);
            p++;
        }
    }
#undef ALLOC_BUF
#undef EMIT_CHAR

    if (dst != NULL) {
        *q = '\0';
        *out = dst;
        *tmp = dst;
    }
    return 1;
}

/*
 * Return the number of characters the formatted output would need, not
 * counting the NUL terminator, or -1 on error.  The format string must
 * already have been through msvc_translate_printf_format().
 */
static int msvc_vscprintf(const char *fmt, va_list args)
{
#if !defined(_MSC_VER) || _MSC_VER >= 1300
    return _vscprintf(fmt, args);
#else
    /*
     * VC6 and older have no _vscprintf(), so the length has to be discovered
     * the hard way: format into a scratch buffer, growing it until the output
     * fits.  _vsnprintf() returns -1 for as long as it does not.
     */
    size_t sz = 256;

    while (sz <= 1024 * 1024) {
        va_list args_copy;
        char *scratch = (char *)OPENSSL_malloc(sz);
        int ret;

        if (scratch == NULL)
            return -1;
        va_copy(args_copy, args);
        ret = _vsnprintf(scratch, sz, fmt, args_copy);
        va_end(args_copy);
        OPENSSL_free(scratch);
        if (ret >= 0)
            return ret;
        sz *= 2;
    }
    return -1;
#endif
}

int vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
    int count = -1;
    va_list args_copy;
    char *fmt_alloc = NULL;
    const char *fmt;

    if (!msvc_translate_printf_format(format, &fmt, &fmt_alloc))
        goto done;

    va_copy(args_copy, args);
    count = msvc_vscprintf(fmt, args_copy);
    va_end(args_copy);

    if (count < 0)
        goto done;

    if (n > 0) {
#if !defined(_MSC_VER) || _MSC_VER >= 1400
        (void)_vsnprintf_s(buf, n, _TRUNCATE, fmt, args);
#else
        /*
         * VC6 to VS2003: _vsnprintf() does not NUL-terminate when the output
         * is truncated, but C99 requires it.
         */
        int written = _vsnprintf(buf, n, fmt, args);

        if (written < 0 || (size_t)written >= n)
            buf[n - 1] = '\0';
#endif
    }

done:
    OPENSSL_free(fmt_alloc);
    return count;
}

int snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vsnprintf(buf, n, fmt, args);
    va_end(args);
    return ret;
}

#else

/*
 * Every other toolchain already provides C99 snprintf() and vsnprintf().
 * ISO C does not allow an empty translation unit, so leave a typedef behind.
 */
typedef int msvc2013_snprintf_unused_t;

#endif /* defined(_MSC_VER) && _MSC_VER < 1900 */
