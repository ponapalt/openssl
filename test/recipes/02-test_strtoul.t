#! /usr/bin/env perl
# Copyright 2015-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test::Simple;
use OpenSSL::Test;
use OpenSSL::Test::Utils;

BEGIN {
    setup("strotoultest");
}

plan tests => 1;

ok(run(test(["strtoultest"])), "running strtoul test");
