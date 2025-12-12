/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include "internal/cryptlib.h"
#include "crypto/ctype.h"
#include "internal/numbers.h"
#include <openssl/bio.h>
#include <openssl/configuration.h>

/* Compatibility for old MSVC versions */
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

int BIO_printf(BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);

    ret = BIO_vprintf(bio, format, args);

    va_end(args);
    return ret;
}

#if defined(_WIN32)
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

#if _MSC_VER < 1900
/*
 * Convert C99 printf format specifiers to old MSVC format specifiers.
 * Old MSVC (before VS2015) doesn't support C99 format specifiers like %lld.
 * This function converts them to MSVC-specific format specifiers like %I64d.
 *
 * Returns a newly allocated string that must be freed by the caller,
 * or NULL if memory allocation fails.
 */
static char *convert_format_for_old_msvc(const char *format)
{
    const char *src;
    char *dst, *result;
    size_t len;
    int in_format;

    /* Calculate the maximum possible length after conversion */
    len = strlen(format);
    /* 'll' (2 chars) -> 'I64' (3 chars), so add extra space */
    len += len / 2 + 1;

    result = (char *)OPENSSL_malloc(len);
    if (result == NULL)
        return NULL;

    src = format;
    dst = result;
    in_format = 0;

    while (*src != '\0') {
        if (*src == '%') {
            *dst++ = *src++;
            if (*src == '%') {
                /* Escaped percent sign */
                *dst++ = *src++;
                continue;
            }
            in_format = 1;
        }

        if (in_format) {
            /* Skip flags: -, +, space, #, 0 */
            while (*src == '-' || *src == '+' || *src == ' ' ||
                   *src == '#' || *src == '0') {
                *dst++ = *src++;
            }

            /* Skip width */
            while (*src >= '0' && *src <= '9') {
                *dst++ = *src++;
            }
            if (*src == '*') {
                *dst++ = *src++;
            }

            /* Skip precision */
            if (*src == '.') {
                *dst++ = *src++;
                while (*src >= '0' && *src <= '9') {
                    *dst++ = *src++;
                }
                if (*src == '*') {
                    *dst++ = *src++;
                }
            }

            /* Check for 'll' length modifier and convert to 'I64' */
            if (src[0] == 'l' && src[1] == 'l') {
                src += 2;  /* Skip 'll' */
                *dst++ = 'I';
                *dst++ = '6';
                *dst++ = '4';
                /* Copy the conversion specifier */
                if (*src != '\0') {
                    *dst++ = *src++;
                }
                in_format = 0;
            } else if (src[0] == 'h' && src[1] == 'h') {
                /*
                 * 'hh' is not supported by old MSVC. Simply skip it.
                 * The argument is promoted to int anyway, so %d works.
                 */
                src += 2;
                /* Copy the conversion specifier */
                if (*src != '\0') {
                    *dst++ = *src++;
                }
                in_format = 0;
            } else if (*src == 'h' || *src == 'l' || *src == 'L' ||
                       *src == 'z' || *src == 't' || *src == 'j') {
                /* Other length modifiers */
                if (*src == 'z') {
                    /* %zd -> %Id on 32-bit, %I64d on 64-bit (size_t) */
                    src++;
#if defined(_WIN64)
                    *dst++ = 'I';
                    *dst++ = '6';
                    *dst++ = '4';
#else
                    *dst++ = 'I';
#endif
                } else if (*src == 't') {
                    /* %td -> %Id on 32-bit, %I64d on 64-bit (ptrdiff_t) */
                    src++;
#if defined(_WIN64)
                    *dst++ = 'I';
                    *dst++ = '6';
                    *dst++ = '4';
#else
                    *dst++ = 'I';
#endif
                } else if (*src == 'j') {
                    /* %jd -> %I64d (intmax_t is always 64-bit on Windows) */
                    src++;
                    *dst++ = 'I';
                    *dst++ = '6';
                    *dst++ = '4';
                } else {
                    /* Single 'h', 'l', or 'L' - supported by old MSVC */
                    *dst++ = *src++;
                }
                /* Copy the conversion specifier */
                if (*src != '\0') {
                    *dst++ = *src++;
                }
                in_format = 0;
            } else {
                /* No length modifier, just copy conversion specifier */
                if (*src != '\0') {
                    *dst++ = *src++;
                }
                in_format = 0;
            }
        } else {
            *dst++ = *src++;
        }
    }

    *dst = '\0';
    return result;
}
#endif

static int msvc_bio_vprintf(BIO *bio, const char *format, va_list args)
{
    char buf[512];
    char *abuf;
    int ret, sz;
#if _MSC_VER < 1900
    char *converted_format;
    va_list args_copy;
#endif

#if _MSC_VER < 1900
    /* Convert C99 format specifiers to old MSVC format specifiers */
    converted_format = convert_format_for_old_msvc(format);
    if (converted_format == NULL)
        return -1;
    format = converted_format;
    va_copy(args_copy, args);
#endif

#if _MSC_VER >= 1400
    /* VS2005 and later: use _vsnprintf_s */
    sz = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, format, args);
#else
    /* Older MSVC: use _vsnprintf */
    sz = _vsnprintf(buf, sizeof(buf), format, args);
#endif

    if (sz == -1) {
        /* Buffer was too small, need to allocate larger buffer */
#if _MSC_VER >= 1300
        /* VS2002 and later: use _vscprintf to get required size */
        sz = _vscprintf(format, args_copy) + 1;
#else
        /* VC6 and older: _vscprintf not available, try larger buffer */
        sz = sizeof(buf) * 4;  /* Start with 2048 bytes */
#endif
        abuf = (char *)OPENSSL_malloc(sz);
        if (abuf == NULL) {
            ret = -1;
        } else {
#if _MSC_VER < 1300
            /* VC6: may need to retry with even larger buffer */
            {
                size_t current_sz = sz;
                va_copy(args_copy, args);
                sz = _vsnprintf(abuf, current_sz, format, args_copy);
                while (sz == -1) {
                    /* Buffer still too small, double it */
                    size_t new_sz = current_sz * 2;
                    char *new_abuf;
                    if (new_sz > 1024 * 1024) {
                        /* Sanity limit: 1MB */
                        OPENSSL_free(abuf);
                        ret = -1;
                        goto cleanup;
                    }
                    new_abuf = (char *)OPENSSL_realloc(abuf, new_sz);
                    if (new_abuf == NULL) {
                        OPENSSL_free(abuf);
                        ret = -1;
                        goto cleanup;
                    }
                    abuf = new_abuf;
                    current_sz = new_sz;
                    va_copy(args_copy, args);
                    sz = _vsnprintf(abuf, current_sz, format, args_copy);
                }
            }
#else
            sz = _vsnprintf(abuf, sz, format, args_copy);
#endif
            ret = BIO_write(bio, abuf, sz);
            OPENSSL_free(abuf);
        }
    } else {
        ret = BIO_write(bio, buf, sz);
    }

#if _MSC_VER < 1300
cleanup:
#endif
#if _MSC_VER < 1900
    OPENSSL_free(converted_format);
#endif

    return ret;
}

/*
 * This function is for unit test on windows only when built with Visual Studio
 */
int ossl_BIO_snprintf_msvc(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;
#if _MSC_VER < 1900
    char *converted_format;

    /* Convert C99 format specifiers to old MSVC format specifiers */
    converted_format = convert_format_for_old_msvc(format);
    if (converted_format == NULL)
        return -1;
    format = converted_format;
#endif

    va_start(args, format);
#if _MSC_VER >= 1400
    /* VS2005 and later: use _vsnprintf_s */
    ret = _vsnprintf_s(buf, n, _TRUNCATE, format, args);
#else
    /* Older MSVC: use _vsnprintf */
    ret = _vsnprintf(buf, n, format, args);
#endif
    va_end(args);

#if _MSC_VER < 1900
    OPENSSL_free(converted_format);
#endif

    return ret;
}

#endif

int BIO_vprintf(BIO *bio, const char *format, va_list args)
{
    va_list cp_args;
#if !defined(_MSC_VER) || _MSC_VER > 1900
    int sz;
#endif
    int ret = -1;

    va_copy(cp_args, args);
#if defined(_MSC_VER) && _MSC_VER < 1900
    ret = msvc_bio_vprintf(bio, format, cp_args);
#else
    char buf[512];
    char *abuf;
    /*
     * some compilers modify va_list, hence each call to v*printf()
     * should operate with its own instance of va_list. The first
     * call to vsnprintf() here uses args we got in function argument.
     * The second call is going to use cp_args we made earlier.
     */
    sz = vsnprintf(buf, sizeof(buf), format, args);
    if (sz >= 0) {
        if ((size_t)sz > sizeof(buf)) {
            sz += 1;
            abuf = (char *)OPENSSL_malloc(sz);
            if (abuf == NULL) {
                ret = -1;
            } else {
                sz = vsnprintf(abuf, sz, format, cp_args);
                ret = BIO_write(bio, abuf, sz);
                OPENSSL_free(abuf);
            }
        } else {
            /* vsnprintf returns length not including nul-terminator */
            ret = BIO_write(bio, buf, sz);
        }
    }
#endif
    va_end(cp_args);
    return ret;
}

/*
 * For historical reasons BIO_snprintf and friends return a failure for string
 * truncation (-1) instead of the POSIX requirement of a success with the
 * number of characters that would have been written. Upon seeing -1 on
 * return, the caller must treat output buf as unsafe (as a buf with missing
 * nul terminator).
 */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;
#if defined(_MSC_VER) && _MSC_VER < 1900
    char *converted_format;

    /* Convert C99 format specifiers to old MSVC format specifiers */
    converted_format = convert_format_for_old_msvc(format);
    if (converted_format == NULL)
        return -1;
    format = converted_format;
#endif

    va_start(args, format);

#if defined(_MSC_VER) && _MSC_VER >= 1400 && _MSC_VER < 1900
    /* VS2005 to VS2013: use _vsnprintf_s */
    ret = _vsnprintf_s(buf, n, _TRUNCATE, format, args);
#elif defined(_MSC_VER) && _MSC_VER < 1400
    /* VC6 to VS2003: use _vsnprintf */
    ret = _vsnprintf(buf, n, format, args);
#else
    ret = vsnprintf(buf, n, format, args);
    if ((size_t)ret >= n)
        ret = -1;
#endif
    va_end(args);

#if defined(_MSC_VER) && _MSC_VER < 1900
    OPENSSL_free(converted_format);
#endif

    return ret;
}

int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
    int ret;
#if defined(_MSC_VER) && _MSC_VER < 1900
    char *converted_format;

    /* Convert C99 format specifiers to old MSVC format specifiers */
    converted_format = convert_format_for_old_msvc(format);
    if (converted_format == NULL)
        return -1;
    format = converted_format;
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1400 && _MSC_VER < 1900
    /* VS2005 to VS2013: use _vsnprintf_s */
    ret = _vsnprintf_s(buf, n, _TRUNCATE, format, args);
#elif defined(_MSC_VER) && _MSC_VER < 1400
    /* VC6 to VS2003: use _vsnprintf */
    ret = _vsnprintf(buf, n, format, args);
#else
    ret = vsnprintf(buf, n, format, args);
    if ((size_t)ret >= n)
        ret = -1;
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
    OPENSSL_free(converted_format);
#endif

    return ret;
}
