/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ASN1_STRING tests */

#include <stdio.h>

#include <openssl/asn1.h>
#include "testutil.h"

struct abs_get_length_test {
    const char *descr;
    int valid;
    const unsigned char der[20];
    int der_len;
    size_t length;
    int unused_bits;
};

static const struct abs_get_length_test abs_get_length_tests[] = {
    {
        "zero bits",
        1,
        {0x03, 0x01, 0x00},
        3,
        0,
        0
    },
    {
        "zero bits one unused",
        0,
        {0x03, 0x01, 0x01},
        3,
        0,
        0
    },
    {
        "single zero bit",
        1,
        {0x03, 0x02, 0x07, 0x00},
        4,
        1,
        7
    },
    {
        "single one bit",
        1,
        {0x03, 0x02, 0x07, 0x80},
        4,
        1,
        7
    },
    {
        /* XXX - the library pretends this is 03 02 07 80 */
        "invalid: single one bit, seventh bit set",
        1,
        {0x03, 0x02, 0x07, 0xc0},
        4,
        1,
        7
    },
    {
        "x.690, primitive encoding in example 8.6.4.2",
        1,
        {0x03, 0x07, 0x04, 0x0A, 0x3b, 0x5F, 0x29, 0x1c, 0xd0},
        9,
        6,
        4
    },
    {
        /*
         * XXX - the library thinks it "decodes" this but gets it
         * quite wrong. Looks like it uses the unused bits of the
         * first component, and the unused bits octet 04 of the
         * second component somehow becomes part of the value.
         */
        "x.690, constructed encoding in example 8.6.4.2",
        1,
        {0x23, 0x80, 0x03, 0x03, 0x00, 0x0A, 0x3b, 0x03, 0x05, 0x04, 0x5F, 0x29, 0x1c, 0xd0, 0x00, 0x00},
        16,
        7, /* XXX - should be 6. */
        0  /* XXX - should be 4. */
    },
    {
        "RFC 3779, 2.1.1, IPv4 address 10.5.0.4",
        1,
        {0x03, 0x05, 0x00, 0x0a, 0x05, 0x00, 0x04},
        7,
        4,
        0
    },
    {
        "RFC 3779, 2.1.1, IPv4 prefix 10.5.0/23",
        1,
        {0x03, 0x04, 0x01, 0x0a, 0x05, 0x00},
        6,
        3,
        1
    },
    {
        "RFC 3779, 2.1.1, IPv6 address 2001:0:200:3::1",
        1,
        {0x03, 0x11, 0x00, 0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        19,
        16,
        0
    },
    {
        "RFC 3779, 2.1.1, IPv6 prefix 2001:0:200/39",
        1,
        {0x03, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02},
        8,
        5,
        1
    }
};

static int
abs_get_length_test(const struct abs_get_length_test *tbl, int idx)
{
    const struct abs_get_length_test *test = &tbl[idx];
    ASN1_BIT_STRING *abs = NULL;
    const unsigned char *p;
    int unused_bits, ret;
    size_t length;
    int success = 0;

    p = test->der;
    if (!TEST_ptr(abs = d2i_ASN1_BIT_STRING(NULL, &p, test->der_len))) {
        TEST_info("%s, (idx=%d) - d2i_ASN1_BIT_STRING faled", "abs_get_length_test", idx);
        goto err;
    }

    ret = ASN1_BIT_STRING_get_length(abs, &length, &unused_bits);
    if (!TEST_int_eq(test->valid, ret)) {
        TEST_info("%s (idx=%d): %s ASN1_BIT_STRING_get_length want %d, got %d\n",
            "abs_get_length_test", idx, test->descr, test->valid, ret);
        goto err;
    }
    if (!test->valid)
        goto done;

    if (!TEST_size_t_eq(length, test->length)
        || !TEST_int_eq(unused_bits, test->unused_bits)) {
        TEST_info("%s: (idx=%d) %s: want (%zu, %d), got (%zu, %d)\n", "abs_get_length_test",
            idx, test->descr, test->length, test->unused_bits, length,
            unused_bits);
        goto err;
    }

done:
    success = 1;

err:
    ASN1_STRING_free(abs);

    return success;
}

static int
asn1_bit_string_get_length_test(int idx)
{
    return abs_get_length_test(abs_get_length_tests, idx);
}

struct abs_set1_test {
    const char *descr;
    int valid;
    const uint8_t data[20];
    size_t length;
    int unused_bits;
    const unsigned char der[20];
    int der_len;
};

static const struct abs_set1_test abs_set1_tests[] = {
    /* descr, valid, data, length, unused_bits, der, der_len */
    {
        "length too large", 0,
        {0}, (size_t)INT_MAX + 1, 0,
        {0}, 0
    },
    {
        "negative unused bits", 0,
        {0}, 0, -1,
        {0}, 0
    },
    {
        "8 unused bits", 0,
        {0}, 0, 8,
        {0}, 0
    },
    {
        "empty with unused bits", 0,
        {0x00}, 0, 1,
        {0}, 0
    },
    {
        "empty", 1,
        {0x00}, 0, 0,
        {0x03, 0x01, 0x00}, 3
    },
    {
        "single zero bit", 1,
        {0x00}, 1, 7,
        {0x03, 0x02, 0x07, 0x00}, 4
    },
    {
        "single zero bit, with non-zero unused bit 6", 0,
        {0x40}, 1, 7,
        {0}, 0
    },
    {
        "single zero bit, with non-zero unused bit 0", 0,
        {0x01}, 1, 7,
        {0}, 0
    },
    {
        "single one bit", 1,
        {0x80}, 1, 7,
        {0x03, 0x02, 0x07, 0x80}, 4
    },
    {
        "single one bit, with non-zero unused-bit 6", 0,
        {0xc0}, 1, 7,
        {0}, 0
    },
    {
        "single one bit, with non-zero unused-bit 0", 0,
        {0x81}, 1, 7,
        {0}, 0
    },
    {
        "RFC 3779, 2.1.1, IPv4 address 10.5.0.4", 1,
        {0x0a, 0x05, 0x00, 0x04}, 4, 0,
        {0x03, 0x05, 0x00, 0x0a, 0x05, 0x00, 0x04}, 7
    },
    {
        "RFC 3779, 2.1.1, IPv4 address 10.5.0/23", 1,
        {0x0a, 0x05, 0x00}, 3, 1,
        {0x03, 0x04, 0x01, 0x0a, 0x05, 0x00}, 6
    },
    {
        "RFC 3779, 2.1.1, IPv4 address 10.5.0/23, unused bit", 0,
        {0x0a, 0x05, 0x01}, 3, 1,
        {0}, 0
    },
    {
        "RFC 3779, IPv4 address 10.5.0/17", 1,
        {0x0a, 0x05, 0x00}, 3, 7,
        {0x03, 0x04, 0x07, 0x0a, 0x05, 0x00}, 6
    },
    {
        "RFC 3779, IPv4 address 10.5.0/18, unused bit set", 0,
        {0x0a, 0x05, 0x20}, 3, 6,
        {0}, 0
    },
    {
        "RFC 3779, 2.1.1, IPv6 address 2001:0:200:3::1", 1,
        {0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
         0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 16, 0,
        {0x03, 0x11, 0x00, 0x20, 0x01, 0x00, 0x00, 0x02,
         0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x01}, 19
    },
    {
        "RFC 3779, IPv6 address 2001:0:200:3::/127", 1,
        {0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
         0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 16, 1,
        {0x03, 0x11, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02,
         0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00}, 19
    },
    {
        "RFC 3779, IPv6 address 2001:0:200:3::/127, unused bit", 0,
        {0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
         0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 16, 1,
        {0}, 0
    },
    {
        "RFC 3779, 2.1.1, IPv6 address 2001:0:200:3::/39", 1,
        {0x20, 0x01, 0x00, 0x00, 0x02}, 5, 1,
        {0x03, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02}, 8
    },
};

static int
abs_set1_test(const struct abs_set1_test *tbl, int idx)
{
    const struct abs_set1_test *test = &tbl[idx];
    ASN1_BIT_STRING *abs = NULL;
    unsigned char *der = NULL;
    int ret, der_len = 0;
    int success = 0;

    if (!TEST_ptr(abs = ASN1_BIT_STRING_new())) {
        TEST_info("%s: (idx = %d) %s ASN1_BIT_STRING_new()", OPENSSL_FUNC, idx, test->descr);
        goto err;
    }

    ret = ASN1_BIT_STRING_set1(abs, test->data, test->length, test->unused_bits);
    if (!TEST_int_eq(ret, test->valid)) {
        TEST_info("%s: (idx = %d) %s ASN1_BIT_STRING_set1(): want %d, got %d",
            OPENSSL_FUNC, idx, test->descr, test->valid, ret);
        goto err;
    }

    if (!test->valid)
        goto done;

    der = NULL;
    if (!TEST_int_eq((der_len = i2d_ASN1_BIT_STRING(abs, &der)), test->der_len)) {
        TEST_info("%s: (idx=%d), %s i2d_ASN1_BIT_STRING(): want %d, got %d",
            OPENSSL_FUNC, idx, test->descr, test->der_len, der_len);
        if (der_len < 0)
            der_len = 0;
        goto err;
    }

    if (!TEST_mem_eq(der, der_len, test->der, test->der_len)) {
        TEST_info("%s: (idx = %d)  %s DER mismatch", OPENSSL_FUNC, idx, test->descr);
        goto err;
    }

done:
    success = 1;

err:
    ASN1_BIT_STRING_free(abs);
    OPENSSL_clear_free(der, der_len);

    return success;
}

static int
asn1_bit_string_set1_test(int idx)
{
    return abs_set1_test(abs_set1_tests, idx);
}

int setup_tests(void)
{
    ADD_ALL_TESTS(asn1_bit_string_get_length_test, OSSL_NELEM(abs_get_length_tests));
    ADD_ALL_TESTS(asn1_bit_string_set1_test, OSSL_NELEM(abs_set1_tests));
    return 1;
}
