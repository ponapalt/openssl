#! /usr/bin/env perl
# Copyright 2010-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see https://github.com/dot-asm/cryptogams/.
# ====================================================================

# AES for MIPS

# October 2010
#
# Code uses 1K[+256B] S-box and on single-issue core [such as R5000]
# spends ~68 cycles per byte processed with 128-bit key. This is ~16%
# faster than gcc-generated code, which is not very impressive. But
# recall that compressed S-box requires extra processing, namely
# additional rotations. Rotations are implemented with lwl/lwr pairs,
# which is normally used for loading unaligned data. Another cool
# thing about this module is its endian neutrality, which means that
# it processes data without ever changing byte order...

# September 2012
#
# Add MIPS32R2 (~10% less instructions) and SmartMIPS ASE (further
# ~25% less instructions) code. Note that there is no run-time switch,
# instead, code path is chosen upon pre-process time, pass -mips32r2
# or/and -msmartmips.

# February 2019
#
# Normalize MIPS32R2 AES table address calculation by always using EXT
# instruction. This reduces the standard codebase by another 10%. 

######################################################################
# There is a number of MIPS ABI in use, O32 and N32/64 are most
# widely used. Then there is a new contender: NUBI. It appears that if
# one picks the latter, it's possible to arrange code in ABI neutral
# manner. Therefore let's stick to NUBI register layout:
#
($zero,$at,$t0,$t1,$t2)=map("\$$_",(0..2,24,25));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$$_",(4..11));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("\$$_",(12..23));
($gp,$tp,$sp,$fp,$ra)=map("\$$_",(3,28..31));
#
# The return value is placed in $a0. Following coding rules facilitate
# interoperability:
#
# - never ever touch $tp, "thread pointer", former $gp;
# - copy return value to $t0, former $v0 [or to $a0 if you're adapting
#   old code];
# - on O32 populate $a4-$a7 with 'lw $aN,4*N($sp)' if necessary;
#
# For reference here is register layout for N32/64 MIPS ABIs:
#
# ($zero,$at,$v0,$v1)=map("\$$_",(0..3));
# ($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$$_",(4..11));
# ($t0,$t1,$t2,$t3,$t8,$t9)=map("\$$_",(12..15,24,25));
# ($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7)=map("\$$_",(16..23));
# ($gp,$sp,$fp,$ra)=map("\$$_",(28..31));

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;
$flavour ||= "o32"; # supported flavours are o32,n32,64,nubi32,nubi64

if ($flavour =~ /64|n32/i) {
	$PTR_LA="dla";
	$PTR_ADD="daddu";	# incidentally works even on n32
	$PTR_SUB="dsubu";	# incidentally works even on n32
	$PTR_INS="dins";
	$REG_S="sd";
	$REG_L="ld";
	$PTR_SLL="dsll";	# incidentally works even on n32
	$SZREG=8;
} else {
	$PTR_LA="la";
	$PTR_ADD="addu";
	$PTR_SUB="subu";
	$PTR_INS="ins";
	$REG_S="sw";
	$REG_L="lw";
	$PTR_SLL="sll";
	$SZREG=4;
}
$pf = ($flavour =~ /nubi/i) ? $t0 : $t2;
#
# <https://github.com/dot-asm>
#
######################################################################

$big_endian=(`echo MIPSEB | $ENV{CC} -E -`=~/MIPSEB/)?0:1 if ($ENV{CC});

if (!defined($big_endian))
{    $big_endian=(unpack('L',pack('N',1))==1);   }

my ($MSB,$LSB)=(0,3);	# automatically converted to little-endian

$output and open STDOUT,">$output";

$code.=<<___;
#include "mips_arch.h"

.text
#if !defined(__mips_eabi) && (!defined(__vxworks) || defined(__pic__))
.option	pic2
#endif
.set	noat
___

{{{
my $FRAMESIZE=16*$SZREG;
my $SAVED_REGS_MASK = ($flavour =~ /nubi/i) ? "0xc0fff008" : "0xc0ff0000";

my ($inp,$out,$key,$Tbl,$s0,$s1,$s2,$s3)=($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7);
my ($i0,$i1,$i2,$i3)=($at,$t0,$t1,$t2);
my ($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8,$t9,$t10,$t11) = map("\$$_",(12..23));
my ($key0,$cnt)=($gp,$fp);

# instruction ordering is "stolen" from output from MIPSpro assembler
# invoked with -mips3 -O3 arguments...
$code.=<<___;
.align	5
.ent	_mips_AES_encrypt
_mips_AES_encrypt:
	.frame	$sp,0,$ra
	.set	reorder
	lw	$t0,0($key)
	lw	$t1,4($key)
	lw	$t2,8($key)
	lw	$t3,12($key)
	lw	$cnt,240($key)
	$PTR_ADD $key0,$key,16

	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3

	subu	$cnt,1
#if defined(__mips_smartmips)
	ext	$i0,$s1,16,8
.Loop_enc:
	ext	$i1,$s2,16,8
	ext	$i2,$s3,16,8
	ext	$i3,$s0,16,8
	lwxs	$t0,$i0($Tbl)		# Te1[s1>>16]
	ext	$i0,$s2,8,8
	lwxs	$t1,$i1($Tbl)		# Te1[s2>>16]
	ext	$i1,$s3,8,8
	lwxs	$t2,$i2($Tbl)		# Te1[s3>>16]
	ext	$i2,$s0,8,8
	lwxs	$t3,$i3($Tbl)		# Te1[s0>>16]
	ext	$i3,$s1,8,8

	lwxs	$t4,$i0($Tbl)		# Te2[s2>>8]
	ext	$i0,$s3,0,8
	lwxs	$t5,$i1($Tbl)		# Te2[s3>>8]
	ext	$i1,$s0,0,8
	lwxs	$t6,$i2($Tbl)		# Te2[s0>>8]
	ext	$i2,$s1,0,8
	lwxs	$t7,$i3($Tbl)		# Te2[s1>>8]
	ext	$i3,$s2,0,8

	lwxs	$t8,$i0($Tbl)		# Te3[s3]
	ext	$i0,$s0,24,8
	lwxs	$t9,$i1($Tbl)		# Te3[s0]
	ext	$i1,$s1,24,8
	lwxs	$t10,$i2($Tbl)		# Te3[s1]
	ext	$i2,$s2,24,8
	lwxs	$t11,$i3($Tbl)		# Te3[s2]
	ext	$i3,$s3,24,8

	rotr	$t0,$t0,8
	rotr	$t1,$t1,8
	rotr	$t2,$t2,8
	rotr	$t3,$t3,8

	rotr	$t4,$t4,16
	rotr	$t5,$t5,16
	rotr	$t6,$t6,16
	rotr	$t7,$t7,16

	xor	$t0,$t4
	lwxs	$t4,$i0($Tbl)		# Te0[s0>>24]
	xor	$t1,$t5
	lwxs	$t5,$i1($Tbl)		# Te0[s1>>24]
	xor	$t2,$t6
	lwxs	$t6,$i2($Tbl)		# Te0[s2>>24]
	xor	$t3,$t7
	lwxs	$t7,$i3($Tbl)		# Te0[s3>>24]

	rotr	$t8,$t8,24
	lw	$s0,0($key0)
	rotr	$t9,$t9,24
	lw	$s1,4($key0)
	rotr	$t10,$t10,24
	lw	$s2,8($key0)
	rotr	$t11,$t11,24
	lw	$s3,12($key0)

	xor	$t0,$t8
	xor	$t1,$t9
	xor	$t2,$t10
	xor	$t3,$t11

	xor	$t0,$t4
	xor	$t1,$t5
	xor	$t2,$t6
	xor	$t3,$t7

	subu	$cnt,1
	$PTR_ADD $key0,16
	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3
	.set	noreorder
	bnez	$cnt,.Loop_enc
	ext	$i0,$s1,16,8

	_xtr	$i0,$s1,16-2
#else
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	move	$i0,$Tbl
	move	$i1,$Tbl
	move	$i2,$Tbl
	move	$i3,$Tbl
	ext	$t0,$s1,16,8
.Loop_enc:
	ext	$t1,$s2,16,8
	ext	$t2,$s3,16,8
	ext	$t3,$s0,16,8
	$PTR_INS $i0,$t0,2,8
	$PTR_INS $i1,$t1,2,8
	$PTR_INS $i2,$t2,2,8
	$PTR_INS $i3,$t3,2,8
	lw	$t0,0($i0)		# Te1[s1>>16]
	ext	$t4,$s2,8,8
	lw	$t1,0($i1)		# Te1[s2>>16]
	ext	$t5,$s3,8,8
	lw	$t2,0($i2)		# Te1[s3>>16]
	ext	$t6,$s0,8,8
	lw	$t3,0($i3)		# Te1[s0>>16]
	ext	$t7,$s1,8,8
	$PTR_INS $i0,$t4,2,8
	$PTR_INS $i1,$t5,2,8
	$PTR_INS $i2,$t6,2,8
	$PTR_INS $i3,$t7,2,8
#else
	_xtr	$i0,$s1,16-2
.Loop_enc:
	_xtr	$i1,$s2,16-2
	_xtr	$i2,$s3,16-2
	_xtr	$i3,$s0,16-2
	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lwl	$t0,3($i0)		# Te1[s1>>16]
	lwl	$t1,3($i1)		# Te1[s2>>16]
	lwl	$t2,3($i2)		# Te1[s3>>16]
	lwl	$t3,3($i3)		# Te1[s0>>16]
	lwr	$t0,2($i0)		# Te1[s1>>16]
	_xtr	$i0,$s2,8-2
	lwr	$t1,2($i1)		# Te1[s2>>16]
	_xtr	$i1,$s3,8-2
	lwr	$t2,2($i2)		# Te1[s3>>16]
	_xtr	$i2,$s0,8-2
	lwr	$t3,2($i3)		# Te1[s0>>16]
	_xtr	$i3,$s1,8-2
	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
#endif
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	rotr	$t0,$t0,8
	rotr	$t1,$t1,8
	rotr	$t2,$t2,8
	rotr	$t3,$t3,8
# if defined(_MIPSEL)
	lw	$t4,0($i0)		# Te2[s2>>8]
	ext	$t8,$s3,0,8
	lw	$t5,0($i1)		# Te2[s3>>8]
	ext	$t9,$s0,0,8
	lw	$t6,0($i2)		# Te2[s0>>8]
	ext	$t10,$s1,0,8
	lw	$t7,0($i3)		# Te2[s1>>8]
	ext	$t11,$s2,0,8
	$PTR_INS $i0,$t8,2,8
	$PTR_INS $i1,$t9,2,8
	$PTR_INS $i2,$t10,2,8
	$PTR_INS $i3,$t11,2,8

	lw	$t8,0($i0)		# Te3[s3]
	$PTR_INS $i0,$s0,2,8
	lw	$t9,0($i1)		# Te3[s0]
	$PTR_INS $i1,$s1,2,8
	lw	$t10,0($i2)		# Te3[s1]
	$PTR_INS $i2,$s2,2,8
	lw	$t11,0($i3)		# Te3[s2]
	$PTR_INS $i3,$s3,2,8
# else
	lw	$t4,0($i0)		# Te2[s2>>8]
	$PTR_INS $i0,$s3,2,8
	lw	$t5,0($i1)		# Te2[s3>>8]
	$PTR_INS $i1,$s0,2,8
	lw	$t6,0($i2)		# Te2[s0>>8]
	$PTR_INS $i2,$s1,2,8
	lw	$t7,0($i3)		# Te2[s1>>8]
	$PTR_INS $i3,$s2,2,8

	lw	$t8,0($i0)		# Te3[s3]
	_xtr	$i0,$s0,24-2
	lw	$t9,0($i1)		# Te3[s0]
	_xtr	$i1,$s1,24-2
	lw	$t10,0($i2)		# Te3[s1]
	_xtr	$i2,$s2,24-2
	lw	$t11,0($i3)		# Te3[s2]
	_xtr	$i3,$s3,24-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
# endif
	rotr	$t4,$t4,16
	rotr	$t5,$t5,16
	rotr	$t6,$t6,16
	rotr	$t7,$t7,16

	rotr	$t8,$t8,24
	rotr	$t9,$t9,24
	rotr	$t10,$t10,24
	rotr	$t11,$t11,24
#else
	lwl	$t4,2($i0)		# Te2[s2>>8]
	lwl	$t5,2($i1)		# Te2[s3>>8]
	lwl	$t6,2($i2)		# Te2[s0>>8]
	lwl	$t7,2($i3)		# Te2[s1>>8]
	lwr	$t4,1($i0)		# Te2[s2>>8]
	_xtr	$i0,$s3,0-2
	lwr	$t5,1($i1)		# Te2[s3>>8]
	_xtr	$i1,$s0,0-2
	lwr	$t6,1($i2)		# Te2[s0>>8]
	_xtr	$i2,$s1,0-2
	lwr	$t7,1($i3)		# Te2[s1>>8]
	_xtr	$i3,$s2,0-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lwl	$t8,1($i0)		# Te3[s3]
	lwl	$t9,1($i1)		# Te3[s0]
	lwl	$t10,1($i2)		# Te3[s1]
	lwl	$t11,1($i3)		# Te3[s2]
	lwr	$t8,0($i0)		# Te3[s3]
	_xtr	$i0,$s0,24-2
	lwr	$t9,0($i1)		# Te3[s0]
	_xtr	$i1,$s1,24-2
	lwr	$t10,0($i2)		# Te3[s1]
	_xtr	$i2,$s2,24-2
	lwr	$t11,0($i3)		# Te3[s2]
	_xtr	$i3,$s3,24-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
#endif
	xor	$t0,$t4
	lw	$t4,0($i0)		# Te0[s0>>24]
	xor	$t1,$t5
	lw	$t5,0($i1)		# Te0[s1>>24]
	xor	$t2,$t6
	lw	$t6,0($i2)		# Te0[s2>>24]
	xor	$t3,$t7
	lw	$t7,0($i3)		# Te0[s3>>24]

	xor	$t0,$t8
	lw	$s0,0($key0)
	xor	$t1,$t9
	lw	$s1,4($key0)
	xor	$t2,$t10
	lw	$s2,8($key0)
	xor	$t3,$t11
	lw	$s3,12($key0)

	xor	$t0,$t4
	xor	$t1,$t5
	xor	$t2,$t6
	xor	$t3,$t7

	subu	$cnt,1
	$PTR_ADD $key0,16
	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3
	.set	noreorder
	bnez	$cnt,.Loop_enc
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	ext	$t0,$s1,16,8
#endif
	_xtr	$i0,$s1,16-2
#endif

	.set	reorder
	_xtr	$i1,$s2,16-2
	_xtr	$i2,$s3,16-2
	_xtr	$i3,$s0,16-2
	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$t0,2($i0)		# Te4[s1>>16]
	_xtr	$i0,$s2,8-2
	lbu	$t1,2($i1)		# Te4[s2>>16]
	_xtr	$i1,$s3,8-2
	lbu	$t2,2($i2)		# Te4[s3>>16]
	_xtr	$i2,$s0,8-2
	lbu	$t3,2($i3)		# Te4[s0>>16]
	_xtr	$i3,$s1,8-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
# if defined(_MIPSEL)
	lbu	$t4,2($i0)		# Te4[s2>>8]
	$PTR_INS $i0,$s0,2,8
	lbu	$t5,2($i1)		# Te4[s3>>8]
	$PTR_INS $i1,$s1,2,8
	lbu	$t6,2($i2)		# Te4[s0>>8]
	$PTR_INS $i2,$s2,2,8
	lbu	$t7,2($i3)		# Te4[s1>>8]
	$PTR_INS $i3,$s3,2,8

	lbu	$t8,2($i0)		# Te4[s0>>24]
	_xtr	$i0,$s3,0-2
	lbu	$t9,2($i1)		# Te4[s1>>24]
	_xtr	$i1,$s0,0-2
	lbu	$t10,2($i2)		# Te4[s2>>24]
	_xtr	$i2,$s1,0-2
	lbu	$t11,2($i3)		# Te4[s3>>24]
	_xtr	$i3,$s2,0-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
# else
	lbu	$t4,2($i0)		# Te4[s2>>8]
	_xtr	$i0,$s0,24-2
	lbu	$t5,2($i1)		# Te4[s3>>8]
	_xtr	$i1,$s1,24-2
	lbu	$t6,2($i2)		# Te4[s0>>8]
	_xtr	$i2,$s2,24-2
	lbu	$t7,2($i3)		# Te4[s1>>8]
	_xtr	$i3,$s3,24-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$t8,2($i0)		# Te4[s0>>24]
	$PTR_INS $i0,$s3,2,8
	lbu	$t9,2($i1)		# Te4[s1>>24]
	$PTR_INS $i1,$s0,2,8
	lbu	$t10,2($i2)		# Te4[s2>>24]
	$PTR_INS $i2,$s1,2,8
	lbu	$t11,2($i3)		# Te4[s3>>24]
	$PTR_INS $i3,$s2,2,8
# endif
	_ins	$t0,16
	_ins	$t1,16
	_ins	$t2,16
	_ins	$t3,16

	_ins2	$t0,$t4,8
	lbu	$t4,2($i0)		# Te4[s3]
	_ins2	$t1,$t5,8
	lbu	$t5,2($i1)		# Te4[s0]
	_ins2	$t2,$t6,8
	lbu	$t6,2($i2)		# Te4[s1]
	_ins2	$t3,$t7,8
	lbu	$t7,2($i3)		# Te4[s2]

	_ins2	$t0,$t8,24
	lw	$s0,0($key0)
	_ins2	$t1,$t9,24
	lw	$s1,4($key0)
	_ins2	$t2,$t10,24
	lw	$s2,8($key0)
	_ins2	$t3,$t11,24
	lw	$s3,12($key0)

	_ins2	$t0,$t4,0
	_ins2	$t1,$t5,0
	_ins2	$t2,$t6,0
	_ins2	$t3,$t7,0
#else
	lbu	$t4,2($i0)		# Te4[s2>>8]
	_xtr	$i0,$s0,24-2
	lbu	$t5,2($i1)		# Te4[s3>>8]
	_xtr	$i1,$s1,24-2
	lbu	$t6,2($i2)		# Te4[s0>>8]
	_xtr	$i2,$s2,24-2
	lbu	$t7,2($i3)		# Te4[s1>>8]
	_xtr	$i3,$s3,24-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$t8,2($i0)		# Te4[s0>>24]
	_xtr	$i0,$s3,0-2
	lbu	$t9,2($i1)		# Te4[s1>>24]
	_xtr	$i1,$s0,0-2
	lbu	$t10,2($i2)		# Te4[s2>>24]
	_xtr	$i2,$s1,0-2
	lbu	$t11,2($i3)		# Te4[s3>>24]
	_xtr	$i3,$s2,0-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl

	_ins	$t0,16
	_ins	$t1,16
	_ins	$t2,16
	_ins	$t3,16

	_ins	$t4,8
	_ins	$t5,8
	_ins	$t6,8
	_ins	$t7,8

	xor	$t0,$t4
	lbu	$t4,2($i0)		# Te4[s3]
	xor	$t1,$t5
	lbu	$t5,2($i1)		# Te4[s0]
	xor	$t2,$t6
	lbu	$t6,2($i2)		# Te4[s1]
	xor	$t3,$t7
	lbu	$t7,2($i3)		# Te4[s2]

	_ins	$t8,24
	lw	$s0,0($key0)
	_ins	$t9,24
	lw	$s1,4($key0)
	_ins	$t10,24
	lw	$s2,8($key0)
	_ins	$t11,24
	lw	$s3,12($key0)

	xor	$t0,$t8
	xor	$t1,$t9
	xor	$t2,$t10
	xor	$t3,$t11

	_ins	$t4,0
	_ins	$t5,0
	_ins	$t6,0
	_ins	$t7,0

	xor	$t0,$t4
	xor	$t1,$t5
	xor	$t2,$t6
	xor	$t3,$t7
#endif
	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3

	jr	$ra
.end	_mips_AES_encrypt

.align	5
.globl	AES_encrypt
.ent	AES_encrypt
AES_encrypt:
	.frame	$sp,$FRAMESIZE,$ra
	.mask	$SAVED_REGS_MASK,-$SZREG
	.set	noreorder
___
$code.=<<___ if ($flavour =~ /o32/i);	# o32 PIC-ification
	.cpload	$pf
___
$code.=<<___;
	$PTR_SUB $sp,$FRAMESIZE
	$REG_S	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_S	$fp,$FRAMESIZE-2*$SZREG($sp)
	$REG_S	$s11,$FRAMESIZE-3*$SZREG($sp)
	$REG_S	$s10,$FRAMESIZE-4*$SZREG($sp)
	$REG_S	$s9,$FRAMESIZE-5*$SZREG($sp)
	$REG_S	$s8,$FRAMESIZE-6*$SZREG($sp)
	$REG_S	$s7,$FRAMESIZE-7*$SZREG($sp)
	$REG_S	$s6,$FRAMESIZE-8*$SZREG($sp)
	$REG_S	$s5,$FRAMESIZE-9*$SZREG($sp)
	$REG_S	$s4,$FRAMESIZE-10*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);	# optimize non-nubi prologue
	$REG_S	\$15,$FRAMESIZE-11*$SZREG($sp)
	$REG_S	\$14,$FRAMESIZE-12*$SZREG($sp)
	$REG_S	\$13,$FRAMESIZE-13*$SZREG($sp)
	$REG_S	\$12,$FRAMESIZE-14*$SZREG($sp)
	$REG_S	$gp,$FRAMESIZE-15*$SZREG($sp)
___
$code.=<<___ if ($flavour !~ /o32/i);	# non-o32 PIC-ification
	.cplocal	$Tbl
	.cpsetup	$pf,$zero,AES_encrypt
___
$code.=<<___;
	.set	reorder
	$PTR_LA	$Tbl,AES_Te		# PIC-ified 'load address'

#if defined(_MIPS_ARCH_MIPS32R6) || defined(_MIPS_ARCH_MIPS64R6)
	lw	$s0,0($inp)
	lw	$s1,4($inp)
	lw	$s2,8($inp)
	lw	$s3,12($inp)
#else
	lwl	$s0,0+$MSB($inp)
	lwl	$s1,4+$MSB($inp)
	lwl	$s2,8+$MSB($inp)
	lwl	$s3,12+$MSB($inp)
	lwr	$s0,0+$LSB($inp)
	lwr	$s1,4+$LSB($inp)
	lwr	$s2,8+$LSB($inp)
	lwr	$s3,12+$LSB($inp)
#endif

	bal	_mips_AES_encrypt

#if defined(_MIPS_ARCH_MIPS32R6) || defined(_MIPS_ARCH_MIPS64R6)
	sw	$s0,0($out)
	sw	$s1,4($out)
	sw	$s2,8($out)
	sw	$s3,12($out)
#else
	swr	$s0,0+$LSB($out)
	swr	$s1,4+$LSB($out)
	swr	$s2,8+$LSB($out)
	swr	$s3,12+$LSB($out)
	swl	$s0,0+$MSB($out)
	swl	$s1,4+$MSB($out)
	swl	$s2,8+$MSB($out)
	swl	$s3,12+$MSB($out)
#endif

	.set	noreorder
	$REG_L	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_L	$fp,$FRAMESIZE-2*$SZREG($sp)
	$REG_L	$s11,$FRAMESIZE-3*$SZREG($sp)
	$REG_L	$s10,$FRAMESIZE-4*$SZREG($sp)
	$REG_L	$s9,$FRAMESIZE-5*$SZREG($sp)
	$REG_L	$s8,$FRAMESIZE-6*$SZREG($sp)
	$REG_L	$s7,$FRAMESIZE-7*$SZREG($sp)
	$REG_L	$s6,$FRAMESIZE-8*$SZREG($sp)
	$REG_L	$s5,$FRAMESIZE-9*$SZREG($sp)
	$REG_L	$s4,$FRAMESIZE-10*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);
	$REG_L	\$15,$FRAMESIZE-11*$SZREG($sp)
	$REG_L	\$14,$FRAMESIZE-12*$SZREG($sp)
	$REG_L	\$13,$FRAMESIZE-13*$SZREG($sp)
	$REG_L	\$12,$FRAMESIZE-14*$SZREG($sp)
	$REG_L	$gp,$FRAMESIZE-15*$SZREG($sp)
___
$code.=<<___;
	jr	$ra
	$PTR_ADD $sp,$FRAMESIZE
.end	AES_encrypt
___

$code.=<<___;
.align	5
.ent	_mips_AES_decrypt
_mips_AES_decrypt:
	.frame	$sp,0,$ra
	.set	reorder
	lw	$t0,0($key)
	lw	$t1,4($key)
	lw	$t2,8($key)
	lw	$t3,12($key)
	lw	$cnt,240($key)
	$PTR_ADD $key0,$key,16

	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3

	subu	$cnt,1
#if defined(__mips_smartmips)
	ext	$i0,$s3,16,8
.Loop_dec:
	ext	$i1,$s0,16,8
	ext	$i2,$s1,16,8
	ext	$i3,$s2,16,8
	lwxs	$t0,$i0($Tbl)		# Td1[s3>>16]
	ext	$i0,$s2,8,8
	lwxs	$t1,$i1($Tbl)		# Td1[s0>>16]
	ext	$i1,$s3,8,8
	lwxs	$t2,$i2($Tbl)		# Td1[s1>>16]
	ext	$i2,$s0,8,8
	lwxs	$t3,$i3($Tbl)		# Td1[s2>>16]
	ext	$i3,$s1,8,8

	lwxs	$t4,$i0($Tbl)		# Td2[s2>>8]
	ext	$i0,$s1,0,8
	lwxs	$t5,$i1($Tbl)		# Td2[s3>>8]
	ext	$i1,$s2,0,8
	lwxs	$t6,$i2($Tbl)		# Td2[s0>>8]
	ext	$i2,$s3,0,8
	lwxs	$t7,$i3($Tbl)		# Td2[s1>>8]
	ext	$i3,$s0,0,8

	lwxs	$t8,$i0($Tbl)		# Td3[s1]
	ext	$i0,$s0,24,8
	lwxs	$t9,$i1($Tbl)		# Td3[s2]
	ext	$i1,$s1,24,8
	lwxs	$t10,$i2($Tbl)		# Td3[s3]
	ext	$i2,$s2,24,8
	lwxs	$t11,$i3($Tbl)		# Td3[s0]
	ext	$i3,$s3,24,8

	rotr	$t0,$t0,8
	rotr	$t1,$t1,8
	rotr	$t2,$t2,8
	rotr	$t3,$t3,8

	rotr	$t4,$t4,16
	rotr	$t5,$t5,16
	rotr	$t6,$t6,16
	rotr	$t7,$t7,16

	xor	$t0,$t4
	lwxs	$t4,$i0($Tbl)		# Td0[s0>>24]
	xor	$t1,$t5
	lwxs	$t5,$i1($Tbl)		# Td0[s1>>24]
	xor	$t2,$t6
	lwxs	$t6,$i2($Tbl)		# Td0[s2>>24]
	xor	$t3,$t7
	lwxs	$t7,$i3($Tbl)		# Td0[s3>>24]

	rotr	$t8,$t8,24
	lw	$s0,0($key0)
	rotr	$t9,$t9,24
	lw	$s1,4($key0)
	rotr	$t10,$t10,24
	lw	$s2,8($key0)
	rotr	$t11,$t11,24
	lw	$s3,12($key0)

	xor	$t0,$t8
	xor	$t1,$t9
	xor	$t2,$t10
	xor	$t3,$t11

	xor	$t0,$t4
	xor	$t1,$t5
	xor	$t2,$t6
	xor	$t3,$t7

	subu	$cnt,1
	$PTR_ADD $key0,16
	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3
	.set	noreorder
	bnez	$cnt,.Loop_dec
	ext	$i0,$s3,16,8

	_xtr	$i0,$s3,16-2
#else
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	move	$i0,$Tbl
	move	$i1,$Tbl
	move	$i2,$Tbl
	move	$i3,$Tbl
	ext	$t0,$s3,16,8
.Loop_dec:
	ext	$t1,$s0,16,8
	ext	$t2,$s1,16,8
	ext	$t3,$s2,16,8
	$PTR_INS $i0,$t0,2,8
	$PTR_INS $i1,$t1,2,8
	$PTR_INS $i2,$t2,2,8
	$PTR_INS $i3,$t3,2,8
	lw	$t0,0($i0)		# Td1[s3>>16]
	ext	$t4,$s2,8,8
	lw	$t1,0($i1)		# Td1[s0>>16]
	ext	$t5,$s3,8,8
	lw	$t2,0($i2)		# Td1[s1>>16]
	ext	$t6,$s0,8,8
	lw	$t3,0($i3)		# Td1[s2>>16]
	ext	$t7,$s1,8,8
	$PTR_INS $i0,$t4,2,8
	$PTR_INS $i1,$t5,2,8
	$PTR_INS $i2,$t6,2,8
	$PTR_INS $i3,$t7,2,8
#else
	_xtr	$i0,$s3,16-2
.Loop_dec:
	_xtr	$i1,$s0,16-2
	_xtr	$i2,$s1,16-2
	_xtr	$i3,$s2,16-2
	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lwl	$t0,3($i0)		# Td1[s3>>16]
	lwl	$t1,3($i1)		# Td1[s0>>16]
	lwl	$t2,3($i2)		# Td1[s1>>16]
	lwl	$t3,3($i3)		# Td1[s2>>16]
	lwr	$t0,2($i0)		# Td1[s3>>16]
	_xtr	$i0,$s2,8-2
	lwr	$t1,2($i1)		# Td1[s0>>16]
	_xtr	$i1,$s3,8-2
	lwr	$t2,2($i2)		# Td1[s1>>16]
	_xtr	$i2,$s0,8-2
	lwr	$t3,2($i3)		# Td1[s2>>16]
	_xtr	$i3,$s1,8-2
	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
#endif
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	rotr	$t0,$t0,8
	rotr	$t1,$t1,8
	rotr	$t2,$t2,8
	rotr	$t3,$t3,8
# if defined(_MIPSEL)
	lw	$t4,0($i0)		# Td2[s2>>8]
	ext	$t8,$s1,0,8
	lw	$t5,0($i1)		# Td2[s3>>8]
	ext	$t9,$s2,0,8
	lw	$t6,0($i2)		# Td2[s0>>8]
	ext	$t10,$s3,0,8
	lw	$t7,0($i3)		# Td2[s1>>8]
	ext	$t11,$s0,0,8
	$PTR_INS $i0,$t8,2,8
	$PTR_INS $i1,$t9,2,8
	$PTR_INS $i2,$t10,2,8
	$PTR_INS $i3,$t11,2,8
	lw	$t8,0($i0)		# Td3[s1]
	$PTR_INS $i0,$s0,2,8
	lw	$t9,0($i1)		# Td3[s2]
	$PTR_INS $i1,$s1,2,8
	lw	$t10,0($i2)		# Td3[s3]
	$PTR_INS $i2,$s2,2,8
	lw	$t11,0($i3)		# Td3[s0]
	$PTR_INS $i3,$s3,2,8
#else
	lw	$t4,0($i0)		# Td2[s2>>8]
	$PTR_INS $i0,$s1,2,8
	lw	$t5,0($i1)		# Td2[s3>>8]
	$PTR_INS $i1,$s2,2,8
	lw	$t6,0($i2)		# Td2[s0>>8]
	$PTR_INS $i2,$s3,2,8
	lw	$t7,0($i3)		# Td2[s1>>8]
	$PTR_INS $i3,$s0,2,8

	lw	$t8,0($i0)		# Td3[s1]
	_xtr	$i0,$s0,24-2
	lw	$t9,0($i1)		# Td3[s2]
	_xtr	$i1,$s1,24-2
	lw	$t10,0($i2)		# Td3[s3]
	_xtr	$i2,$s2,24-2
	lw	$t11,0($i3)		# Td3[s0]
	_xtr	$i3,$s3,24-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
#endif
	rotr	$t4,$t4,16
	rotr	$t5,$t5,16
	rotr	$t6,$t6,16
	rotr	$t7,$t7,16

	rotr	$t8,$t8,24
	rotr	$t9,$t9,24
	rotr	$t10,$t10,24
	rotr	$t11,$t11,24
#else
	lwl	$t4,2($i0)		# Td2[s2>>8]
	lwl	$t5,2($i1)		# Td2[s3>>8]
	lwl	$t6,2($i2)		# Td2[s0>>8]
	lwl	$t7,2($i3)		# Td2[s1>>8]
	lwr	$t4,1($i0)		# Td2[s2>>8]
	_xtr	$i0,$s1,0-2
	lwr	$t5,1($i1)		# Td2[s3>>8]
	_xtr	$i1,$s2,0-2
	lwr	$t6,1($i2)		# Td2[s0>>8]
	_xtr	$i2,$s3,0-2
	lwr	$t7,1($i3)		# Td2[s1>>8]
	_xtr	$i3,$s0,0-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lwl	$t8,1($i0)		# Td3[s1]
	lwl	$t9,1($i1)		# Td3[s2]
	lwl	$t10,1($i2)		# Td3[s3]
	lwl	$t11,1($i3)		# Td3[s0]
	lwr	$t8,0($i0)		# Td3[s1]
	_xtr	$i0,$s0,24-2
	lwr	$t9,0($i1)		# Td3[s2]
	_xtr	$i1,$s1,24-2
	lwr	$t10,0($i2)		# Td3[s3]
	_xtr	$i2,$s2,24-2
	lwr	$t11,0($i3)		# Td3[s0]
	_xtr	$i3,$s3,24-2

	and	$i0,0x3fc
	and	$i1,0x3fc
	and	$i2,0x3fc
	and	$i3,0x3fc
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
#endif

	xor	$t0,$t4
	lw	$t4,0($i0)		# Td0[s0>>24]
	xor	$t1,$t5
	lw	$t5,0($i1)		# Td0[s1>>24]
	xor	$t2,$t6
	lw	$t6,0($i2)		# Td0[s2>>24]
	xor	$t3,$t7
	lw	$t7,0($i3)		# Td0[s3>>24]

	xor	$t0,$t8
	lw	$s0,0($key0)
	xor	$t1,$t9
	lw	$s1,4($key0)
	xor	$t2,$t10
	lw	$s2,8($key0)
	xor	$t3,$t11
	lw	$s3,12($key0)

	xor	$t0,$t4
	xor	$t1,$t5
	xor	$t2,$t6
	xor	$t3,$t7

	subu	$cnt,1
	$PTR_ADD $key0,16
	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3
	.set	noreorder
	bnez	$cnt,.Loop_dec
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	ext	$t0,$s3,16,8
#endif

	_xtr	$i0,$s3,16-2
#endif

	.set	reorder
	lw	$t4,1024($Tbl)		# prefetch Td4
	_xtr	$i0,$s3,16
	lw	$t5,1024+32($Tbl)
	_xtr	$i1,$s0,16
	lw	$t6,1024+64($Tbl)
	_xtr	$i2,$s1,16
	lw	$t7,1024+96($Tbl)
	_xtr	$i3,$s2,16
	lw	$t8,1024+128($Tbl)
	and	$i0,0xff
	lw	$t9,1024+160($Tbl)
	and	$i1,0xff
	lw	$t10,1024+192($Tbl)
	and	$i2,0xff
	lw	$t11,1024+224($Tbl)
	and	$i3,0xff

	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$t0,1024($i0)		# Td4[s3>>16]
	_xtr	$i0,$s2,8
	lbu	$t1,1024($i1)		# Td4[s0>>16]
	_xtr	$i1,$s3,8
	lbu	$t2,1024($i2)		# Td4[s1>>16]
	_xtr	$i2,$s0,8
	lbu	$t3,1024($i3)		# Td4[s2>>16]
	_xtr	$i3,$s1,8

	and	$i0,0xff
	and	$i1,0xff
	and	$i2,0xff
	and	$i3,0xff
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
# if defined(_MIPSEL)
	lbu	$t4,1024($i0)		# Td4[s2>>8]
	$PTR_INS $i0,$s0,0,8
	lbu	$t5,1024($i1)		# Td4[s3>>8]
	$PTR_INS $i1,$s1,0,8
	lbu	$t6,1024($i2)		# Td4[s0>>8]
	$PTR_INS $i2,$s2,0,8
	lbu	$t7,1024($i3)		# Td4[s1>>8]
	$PTR_INS $i3,$s3,0,8

	lbu	$t8,1024($i0)		# Td4[s0>>24]
	_xtr	$i0,$s1,0
	lbu	$t9,1024($i1)		# Td4[s1>>24]
	_xtr	$i1,$s2,0
	lbu	$t10,1024($i2)		# Td4[s2>>24]
	_xtr	$i2,$s3,0
	lbu	$t11,1024($i3)		# Td4[s3>>24]
	_xtr	$i3,$s0,0

	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
# else
	lbu	$t4,1024($i0)		# Td4[s2>>8]
	_xtr	$i0,$s0,24
	lbu	$t5,1024($i1)		# Td4[s3>>8]
	_xtr	$i1,$s1,24
	lbu	$t6,1024($i2)		# Td4[s0>>8]
	_xtr	$i2,$s2,24
	lbu	$t7,1024($i3)		# Td4[s1>>8]
	_xtr	$i3,$s3,24

	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$t8,1024($i0)		# Td4[s0>>24]
	$PTR_INS $i0,$s1,0,8
	lbu	$t9,1024($i1)		# Td4[s1>>24]
	$PTR_INS $i1,$s2,0,8
	lbu	$t10,1024($i2)		# Td4[s2>>24]
	$PTR_INS $i2,$s3,0,8
	lbu	$t11,1024($i3)		# Td4[s3>>24]
	$PTR_INS $i3,$s0,0,8
# endif
	_ins	$t0,16
	_ins	$t1,16
	_ins	$t2,16
	_ins	$t3,16

	_ins2	$t0,$t4,8
	lbu	$t4,1024($i0)		# Td4[s1]
	_ins2	$t1,$t5,8
	lbu	$t5,1024($i1)		# Td4[s2]
	_ins2	$t2,$t6,8
	lbu	$t6,1024($i2)		# Td4[s3]
	_ins2	$t3,$t7,8
	lbu	$t7,1024($i3)		# Td4[s0]

	_ins2	$t0,$t8,24
	lw	$s0,0($key0)
	_ins2	$t1,$t9,24
	lw	$s1,4($key0)
	_ins2	$t2,$t10,24
	lw	$s2,8($key0)
	_ins2	$t3,$t11,24
	lw	$s3,12($key0)

	_ins2	$t0,$t4,0
	_ins2	$t1,$t5,0
	_ins2	$t2,$t6,0
	_ins2	$t3,$t7,0
#else
	lbu	$t4,1024($i0)		# Td4[s2>>8]
	_xtr	$i0,$s0,24
	lbu	$t5,1024($i1)		# Td4[s3>>8]
	_xtr	$i1,$s1,24
	lbu	$t6,1024($i2)		# Td4[s0>>8]
	_xtr	$i2,$s2,24
	lbu	$t7,1024($i3)		# Td4[s1>>8]
	_xtr	$i3,$s3,24

	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$t8,1024($i0)		# Td4[s0>>24]
	_xtr	$i0,$s1,0
	lbu	$t9,1024($i1)		# Td4[s1>>24]
	_xtr	$i1,$s2,0
	lbu	$t10,1024($i2)		# Td4[s2>>24]
	_xtr	$i2,$s3,0
	lbu	$t11,1024($i3)		# Td4[s3>>24]
	_xtr	$i3,$s0,0

	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl

	_ins	$t0,16
	_ins	$t1,16
	_ins	$t2,16
	_ins	$t3,16

	_ins	$t4,8
	_ins	$t5,8
	_ins	$t6,8
	_ins	$t7,8

	xor	$t0,$t4
	lbu	$t4,1024($i0)		# Td4[s1]
	xor	$t1,$t5
	lbu	$t5,1024($i1)		# Td4[s2]
	xor	$t2,$t6
	lbu	$t6,1024($i2)		# Td4[s3]
	xor	$t3,$t7
	lbu	$t7,1024($i3)		# Td4[s0]

	_ins	$t8,24
	lw	$s0,0($key0)
	_ins	$t9,24
	lw	$s1,4($key0)
	_ins	$t10,24
	lw	$s2,8($key0)
	_ins	$t11,24
	lw	$s3,12($key0)

	xor	$t0,$t8
	xor	$t1,$t9
	xor	$t2,$t10
	xor	$t3,$t11

	_ins	$t4,0
	_ins	$t5,0
	_ins	$t6,0
	_ins	$t7,0

	xor	$t0,$t4
	xor	$t1,$t5
	xor	$t2,$t6
	xor	$t3,$t7
#endif

	xor	$s0,$t0
	xor	$s1,$t1
	xor	$s2,$t2
	xor	$s3,$t3

	jr	$ra
.end	_mips_AES_decrypt

.align	5
.globl	AES_decrypt
.ent	AES_decrypt
AES_decrypt:
	.frame	$sp,$FRAMESIZE,$ra
	.mask	$SAVED_REGS_MASK,-$SZREG
	.set	noreorder
___
$code.=<<___ if ($flavour =~ /o32/i);	# o32 PIC-ification
	.cpload	$pf
___
$code.=<<___;
	$PTR_SUB $sp,$FRAMESIZE
	$REG_S	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_S	$fp,$FRAMESIZE-2*$SZREG($sp)
	$REG_S	$s11,$FRAMESIZE-3*$SZREG($sp)
	$REG_S	$s10,$FRAMESIZE-4*$SZREG($sp)
	$REG_S	$s9,$FRAMESIZE-5*$SZREG($sp)
	$REG_S	$s8,$FRAMESIZE-6*$SZREG($sp)
	$REG_S	$s7,$FRAMESIZE-7*$SZREG($sp)
	$REG_S	$s6,$FRAMESIZE-8*$SZREG($sp)
	$REG_S	$s5,$FRAMESIZE-9*$SZREG($sp)
	$REG_S	$s4,$FRAMESIZE-10*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);	# optimize non-nubi prologue
	$REG_S	\$15,$FRAMESIZE-11*$SZREG($sp)
	$REG_S	\$14,$FRAMESIZE-12*$SZREG($sp)
	$REG_S	\$13,$FRAMESIZE-13*$SZREG($sp)
	$REG_S	\$12,$FRAMESIZE-14*$SZREG($sp)
	$REG_S	$gp,$FRAMESIZE-15*$SZREG($sp)
___
$code.=<<___ if ($flavour !~ /o32/i);	# non-o32 PIC-ification
	.cplocal	$Tbl
	.cpsetup	$pf,$zero,AES_decrypt
___
$code.=<<___;
	.set	reorder
	$PTR_LA	$Tbl,AES_Td		# PIC-ified 'load address'

#if defined(_MIPS_ARCH_MIPS32R6) || defined(_MIPS_ARCH_MIPS64R6)
	lw	$s0,0($inp)
	lw	$s1,4($inp)
	lw	$s2,8($inp)
	lw	$s3,12($inp)
#else
	lwl	$s0,0+$MSB($inp)
	lwl	$s1,4+$MSB($inp)
	lwl	$s2,8+$MSB($inp)
	lwl	$s3,12+$MSB($inp)
	lwr	$s0,0+$LSB($inp)
	lwr	$s1,4+$LSB($inp)
	lwr	$s2,8+$LSB($inp)
	lwr	$s3,12+$LSB($inp)
#endif

	bal	_mips_AES_decrypt

#if defined(_MIPS_ARCH_MIPS32R6) || defined(_MIPS_ARCH_MIPS64R6)
	sw	$s0,0($out)
	sw	$s1,4($out)
	sw	$s2,8($out)
	sw	$s3,12($out)
#else
	swr	$s0,0+$LSB($out)
	swr	$s1,4+$LSB($out)
	swr	$s2,8+$LSB($out)
	swr	$s3,12+$LSB($out)
	swl	$s0,0+$MSB($out)
	swl	$s1,4+$MSB($out)
	swl	$s2,8+$MSB($out)
	swl	$s3,12+$MSB($out)
#endif

	.set	noreorder
	$REG_L	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_L	$fp,$FRAMESIZE-2*$SZREG($sp)
	$REG_L	$s11,$FRAMESIZE-3*$SZREG($sp)
	$REG_L	$s10,$FRAMESIZE-4*$SZREG($sp)
	$REG_L	$s9,$FRAMESIZE-5*$SZREG($sp)
	$REG_L	$s8,$FRAMESIZE-6*$SZREG($sp)
	$REG_L	$s7,$FRAMESIZE-7*$SZREG($sp)
	$REG_L	$s6,$FRAMESIZE-8*$SZREG($sp)
	$REG_L	$s5,$FRAMESIZE-9*$SZREG($sp)
	$REG_L	$s4,$FRAMESIZE-10*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);
	$REG_L	\$15,$FRAMESIZE-11*$SZREG($sp)
	$REG_L	\$14,$FRAMESIZE-12*$SZREG($sp)
	$REG_L	\$13,$FRAMESIZE-13*$SZREG($sp)
	$REG_L	\$12,$FRAMESIZE-14*$SZREG($sp)
	$REG_L	$gp,$FRAMESIZE-15*$SZREG($sp)
___
$code.=<<___;
	jr	$ra
	$PTR_ADD $sp,$FRAMESIZE
.end	AES_decrypt
___
}}}

{{{
my $FRAMESIZE=8*$SZREG;
my $SAVED_REGS_MASK = ($flavour =~ /nubi/i) ? "0xc000f008" : "0xc0000000";

my ($inp,$bits,$key,$Tbl)=($a0,$a1,$a2,$a3);
my ($rk0,$rk1,$rk2,$rk3,$rk4,$rk5,$rk6,$rk7)=($a4,$a5,$a6,$a7,$s0,$s1,$s2,$s3);
my ($i0,$i1,$i2,$i3)=($at,$t0,$t1,$t2);
my ($rcon,$cnt)=($gp,$fp);

$code.=<<___;
.align	5
.ent	_mips_AES_set_encrypt_key
_mips_AES_set_encrypt_key:
	.frame	$sp,0,$ra
	.set	noreorder
	beqz	$inp,.Lekey_done
	li	$t0,-1
	beqz	$key,.Lekey_done
	$PTR_ADD $rcon,$Tbl,256

	.set	reorder
#if defined(_MIPS_ARCH_MIPS32R6) || defined(_MIPS_ARCH_MIPS64R6)
	lw	$rk0,0($inp)		# load 128 bits
	lw	$rk1,4($inp)
	lw	$rk2,8($inp)
	lw	$rk3,12($inp)
#else
	lwl	$rk0,0+$MSB($inp)	# load 128 bits
	lwl	$rk1,4+$MSB($inp)
	lwl	$rk2,8+$MSB($inp)
	lwl	$rk3,12+$MSB($inp)
	lwr	$rk0,0+$LSB($inp)
	lwr	$rk1,4+$LSB($inp)
	lwr	$rk2,8+$LSB($inp)
	lwr	$rk3,12+$LSB($inp)
#endif
	li	$at,128
	.set	noreorder
	beq	$bits,$at,.L128bits
	li	$cnt,10

	.set	reorder
#if defined(_MIPS_ARCH_MIPS32R6) || defined(_MIPS_ARCH_MIPS64R6)
	lw	$rk4,16($inp)		# load 192 bits
	lw	$rk5,20($inp)
#else
	lwl	$rk4,16+$MSB($inp)	# load 192 bits
	lwl	$rk5,20+$MSB($inp)
	lwr	$rk4,16+$LSB($inp)
	lwr	$rk5,20+$LSB($inp)
#endif
	li	$at,192
	.set	noreorder
	beq	$bits,$at,.L192bits
	li	$cnt,8

	.set	reorder
#if defined(_MIPS_ARCH_MIPS32R6) || defined(_MIPS_ARCH_MIPS64R6)
	lw	$rk6,24($inp)		# load 256 bits
	lw	$rk7,28($inp)
#else
	lwl	$rk6,24+$MSB($inp)	# load 256 bits
	lwl	$rk7,28+$MSB($inp)
	lwr	$rk6,24+$LSB($inp)
	lwr	$rk7,28+$LSB($inp)
#endif
	li	$at,256
	.set	noreorder
	beq	$bits,$at,.L256bits
	li	$cnt,7

	b	.Lekey_done
	li	$t0,-2

.align	4
.L128bits:
	.set	reorder
	srl	$i0,$rk3,16
	srl	$i1,$rk3,8
	and	$i0,0xff
	and	$i1,0xff
	and	$i2,$rk3,0xff
	srl	$i3,$rk3,24
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$i0,0($i0)
	lbu	$i1,0($i1)
	lbu	$i2,0($i2)
	lbu	$i3,0($i3)

	sw	$rk0,0($key)
	sw	$rk1,4($key)
	sw	$rk2,8($key)
	sw	$rk3,12($key)
	subu	$cnt,1
	$PTR_ADD $key,16

	_bias	$i0,24
	_bias	$i1,16
	_bias	$i2,8
	_bias	$i3,0

	xor	$rk0,$i0
	lw	$i0,0($rcon)
	xor	$rk0,$i1
	xor	$rk0,$i2
	xor	$rk0,$i3
	xor	$rk0,$i0

	xor	$rk1,$rk0
	xor	$rk2,$rk1
	xor	$rk3,$rk2

	.set	noreorder
	bnez	$cnt,.L128bits
	$PTR_ADD $rcon,4

	sw	$rk0,0($key)
	sw	$rk1,4($key)
	sw	$rk2,8($key)
	li	$cnt,10
	sw	$rk3,12($key)
	li	$t0,0
	sw	$cnt,80($key)
	b	.Lekey_done
	$PTR_SUB $key,10*16

.align	4
.L192bits:
	.set	reorder
	srl	$i0,$rk5,16
	srl	$i1,$rk5,8
	and	$i0,0xff
	and	$i1,0xff
	and	$i2,$rk5,0xff
	srl	$i3,$rk5,24
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$i0,0($i0)
	lbu	$i1,0($i1)
	lbu	$i2,0($i2)
	lbu	$i3,0($i3)

	sw	$rk0,0($key)
	sw	$rk1,4($key)
	sw	$rk2,8($key)
	sw	$rk3,12($key)
	sw	$rk4,16($key)
	sw	$rk5,20($key)
	subu	$cnt,1
	$PTR_ADD $key,24

	_bias	$i0,24
	_bias	$i1,16
	_bias	$i2,8
	_bias	$i3,0

	xor	$rk0,$i0
	lw	$i0,0($rcon)
	xor	$rk0,$i1
	xor	$rk0,$i2
	xor	$rk0,$i3
	xor	$rk0,$i0

	xor	$rk1,$rk0
	xor	$rk2,$rk1
	xor	$rk3,$rk2
	xor	$rk4,$rk3
	xor	$rk5,$rk4

	.set	noreorder
	bnez	$cnt,.L192bits
	$PTR_ADD $rcon,4

	sw	$rk0,0($key)
	sw	$rk1,4($key)
	sw	$rk2,8($key)
	li	$cnt,12
	sw	$rk3,12($key)
	li	$t0,0
	sw	$cnt,48($key)
	b	.Lekey_done
	$PTR_SUB $key,12*16

.align	4
.L256bits:
	.set	reorder
	srl	$i0,$rk7,16
	srl	$i1,$rk7,8
	and	$i0,0xff
	and	$i1,0xff
	and	$i2,$rk7,0xff
	srl	$i3,$rk7,24
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$i0,0($i0)
	lbu	$i1,0($i1)
	lbu	$i2,0($i2)
	lbu	$i3,0($i3)

	sw	$rk0,0($key)
	sw	$rk1,4($key)
	sw	$rk2,8($key)
	sw	$rk3,12($key)
	sw	$rk4,16($key)
	sw	$rk5,20($key)
	sw	$rk6,24($key)
	sw	$rk7,28($key)
	subu	$cnt,1

	_bias	$i0,24
	_bias	$i1,16
	_bias	$i2,8
	_bias	$i3,0

	xor	$rk0,$i0
	lw	$i0,0($rcon)
	xor	$rk0,$i1
	xor	$rk0,$i2
	xor	$rk0,$i3
	xor	$rk0,$i0

	xor	$rk1,$rk0
	xor	$rk2,$rk1
	xor	$rk3,$rk2
	beqz	$cnt,.L256bits_done

	srl	$i0,$rk3,24
	srl	$i1,$rk3,16
	srl	$i2,$rk3,8
	and	$i3,$rk3,0xff
	and	$i1,0xff
	and	$i2,0xff
	$PTR_ADD $i0,$Tbl
	$PTR_ADD $i1,$Tbl
	$PTR_ADD $i2,$Tbl
	$PTR_ADD $i3,$Tbl
	lbu	$i0,0($i0)
	lbu	$i1,0($i1)
	lbu	$i2,0($i2)
	lbu	$i3,0($i3)
	sll	$i0,24
	sll	$i1,16
	sll	$i2,8

	xor	$rk4,$i0
	xor	$rk4,$i1
	xor	$rk4,$i2
	xor	$rk4,$i3

	xor	$rk5,$rk4
	xor	$rk6,$rk5
	xor	$rk7,$rk6

	$PTR_ADD $key,32
	.set	noreorder
	b	.L256bits
	$PTR_ADD $rcon,4

.L256bits_done:
	sw	$rk0,32($key)
	sw	$rk1,36($key)
	sw	$rk2,40($key)
	li	$cnt,14
	sw	$rk3,44($key)
	li	$t0,0
	sw	$cnt,48($key)
	$PTR_SUB $key,12*16

.Lekey_done:
	jr	$ra
	nop
.end	_mips_AES_set_encrypt_key

.globl	AES_set_encrypt_key
.ent	AES_set_encrypt_key
AES_set_encrypt_key:
	.frame	$sp,$FRAMESIZE,$ra
	.mask	$SAVED_REGS_MASK,-$SZREG
	.set	noreorder
___
$code.=<<___ if ($flavour =~ /o32/i);	# o32 PIC-ification
	.cpload	$pf
___
$code.=<<___;
	$PTR_SUB $sp,$FRAMESIZE
	$REG_S	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_S	$fp,$FRAMESIZE-2*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);	# optimize non-nubi prologue
	$REG_S	$s3,$FRAMESIZE-3*$SZREG($sp)
	$REG_S	$s2,$FRAMESIZE-4*$SZREG($sp)
	$REG_S	$s1,$FRAMESIZE-5*$SZREG($sp)
	$REG_S	$s0,$FRAMESIZE-6*$SZREG($sp)
	$REG_S	$gp,$FRAMESIZE-7*$SZREG($sp)
___
$code.=<<___ if ($flavour !~ /o32/i);	# non-o32 PIC-ification
	.cplocal	$Tbl
	.cpsetup	$pf,$zero,AES_set_encrypt_key
___
$code.=<<___;
	.set	reorder
	$PTR_LA	$Tbl,AES_Te4		# PIC-ified 'load address'

	bal	_mips_AES_set_encrypt_key

	.set	noreorder
	move	$a0,$t0
	$REG_L	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_L	$fp,$FRAMESIZE-2*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);
	$REG_L	$s3,$FRAMESIZE-11*$SZREG($sp)
	$REG_L	$s2,$FRAMESIZE-12*$SZREG($sp)
	$REG_L	$s1,$FRAMESIZE-13*$SZREG($sp)
	$REG_L	$s0,$FRAMESIZE-14*$SZREG($sp)
	$REG_L	$gp,$FRAMESIZE-15*$SZREG($sp)
___
$code.=<<___;
	jr	$ra
	$PTR_ADD $sp,$FRAMESIZE
.end	AES_set_encrypt_key
___

my ($head,$tail)=($inp,$bits);
my ($tp1,$tp2,$tp4,$tp8,$tp9,$tpb,$tpd,$tpe)=($a4,$a5,$a6,$a7,$s0,$s1,$s2,$s3);
my ($m,$x80808080,$x7f7f7f7f,$x1b1b1b1b)=($at,$t0,$t1,$t2);
$code.=<<___;
.align	5
.globl	AES_set_decrypt_key
.ent	AES_set_decrypt_key
AES_set_decrypt_key:
	.frame	$sp,$FRAMESIZE,$ra
	.mask	$SAVED_REGS_MASK,-$SZREG
	.set	noreorder
___
$code.=<<___ if ($flavour =~ /o32/i);	# o32 PIC-ification
	.cpload	$pf
___
$code.=<<___;
	$PTR_SUB $sp,$FRAMESIZE
	$REG_S	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_S	$fp,$FRAMESIZE-2*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);	# optimize non-nubi prologue
	$REG_S	$s3,$FRAMESIZE-3*$SZREG($sp)
	$REG_S	$s2,$FRAMESIZE-4*$SZREG($sp)
	$REG_S	$s1,$FRAMESIZE-5*$SZREG($sp)
	$REG_S	$s0,$FRAMESIZE-6*$SZREG($sp)
	$REG_S	$gp,$FRAMESIZE-7*$SZREG($sp)
___
$code.=<<___ if ($flavour !~ /o32/i);	# non-o32 PIC-ification
	.cplocal	$Tbl
	.cpsetup	$pf,$zero,AES_set_decrypt_key
___
$code.=<<___;
	.set	reorder
	$PTR_LA	$Tbl,AES_Te4		# PIC-ified 'load address'

	bal	_mips_AES_set_encrypt_key

	bltz	$t0,.Ldkey_done

	sll	$at,$cnt,4
	$PTR_ADD $head,$key,0
	$PTR_ADD $tail,$key,$at
.align	4
.Lswap:
	lw	$rk0,0($head)
	lw	$rk1,4($head)
	lw	$rk2,8($head)
	lw	$rk3,12($head)
	lw	$rk4,0($tail)
	lw	$rk5,4($tail)
	lw	$rk6,8($tail)
	lw	$rk7,12($tail)
	sw	$rk0,0($tail)
	sw	$rk1,4($tail)
	sw	$rk2,8($tail)
	sw	$rk3,12($tail)
	$PTR_ADD $head,16
	$PTR_SUB $tail,16
	sw	$rk4,-16($head)
	sw	$rk5,-12($head)
	sw	$rk6,-8($head)
	sw	$rk7,-4($head)
	bne	$head,$tail,.Lswap

	lw	$tp1,16($key)		# modulo-scheduled
	lui	$x80808080,0x8080
	subu	$cnt,1
	or	$x80808080,0x8080
	sll	$cnt,2
	$PTR_ADD $key,16
	lui	$x1b1b1b1b,0x1b1b
	nor	$x7f7f7f7f,$zero,$x80808080
	or	$x1b1b1b1b,0x1b1b
.align	4
.Lmix:
	and	$m,$tp1,$x80808080
	and	$tp2,$tp1,$x7f7f7f7f
	srl	$tp4,$m,7
	addu	$tp2,$tp2		# tp2<<1
	subu	$m,$tp4
	and	$m,$x1b1b1b1b
	xor	$tp2,$m

	and	$m,$tp2,$x80808080
	and	$tp4,$tp2,$x7f7f7f7f
	srl	$tp8,$m,7
	addu	$tp4,$tp4		# tp4<<1
	subu	$m,$tp8
	and	$m,$x1b1b1b1b
	xor	$tp4,$m

	and	$m,$tp4,$x80808080
	and	$tp8,$tp4,$x7f7f7f7f
	srl	$tp9,$m,7
	addu	$tp8,$tp8		# tp8<<1
	subu	$m,$tp9
	and	$m,$x1b1b1b1b
	xor	$tp8,$m

	xor	$tp9,$tp8,$tp1
	xor	$tpe,$tp8,$tp4
	xor	$tpb,$tp9,$tp2
	xor	$tpd,$tp9,$tp4

#if defined(_MIPS_ARCH_MIPS32R2) || defined(_MIPS_ARCH_MIPS64R2)
	rotr	$tp1,$tpd,16
	 xor	$tpe,$tp2
	rotr	$tp2,$tp9,8
	xor	$tpe,$tp1
	rotr	$tp4,$tpb,24
	xor	$tpe,$tp2
	lw	$tp1,4($key)		# modulo-scheduled
	xor	$tpe,$tp4
#else
	_ror	$tp1,$tpd,16
	 xor	$tpe,$tp2
	_ror	$tp2,$tpd,-16
	xor	$tpe,$tp1
	_ror	$tp1,$tp9,8
	xor	$tpe,$tp2
	_ror	$tp2,$tp9,-24
	xor	$tpe,$tp1
	_ror	$tp1,$tpb,24
	xor	$tpe,$tp2
	_ror	$tp2,$tpb,-8
	xor	$tpe,$tp1
	lw	$tp1,4($key)		# modulo-scheduled
	xor	$tpe,$tp2
#endif
	subu	$cnt,1
	sw	$tpe,0($key)
	$PTR_ADD $key,4
	bnez	$cnt,.Lmix

	li	$t0,0
.Ldkey_done:
	.set	noreorder
	move	$a0,$t0
	$REG_L	$ra,$FRAMESIZE-1*$SZREG($sp)
	$REG_L	$fp,$FRAMESIZE-2*$SZREG($sp)
___
$code.=<<___ if ($flavour =~ /nubi/i);
	$REG_L	$s3,$FRAMESIZE-11*$SZREG($sp)
	$REG_L	$s2,$FRAMESIZE-12*$SZREG($sp)
	$REG_L	$s1,$FRAMESIZE-13*$SZREG($sp)
	$REG_L	$s0,$FRAMESIZE-14*$SZREG($sp)
	$REG_L	$gp,$FRAMESIZE-15*$SZREG($sp)
___
$code.=<<___;
	jr	$ra
	$PTR_ADD $sp,$FRAMESIZE
.end	AES_set_decrypt_key
___
}}}

######################################################################
# Tables are kept in endian-neutral manner
$code.=<<___;
.rdata
.align	10
AES_Te:
.byte	0xc6,0x63,0x63,0xa5,	0xf8,0x7c,0x7c,0x84	# Te0
.byte	0xee,0x77,0x77,0x99,	0xf6,0x7b,0x7b,0x8d
.byte	0xff,0xf2,0xf2,0x0d,	0xd6,0x6b,0x6b,0xbd
.byte	0xde,0x6f,0x6f,0xb1,	0x91,0xc5,0xc5,0x54
.byte	0x60,0x30,0x30,0x50,	0x02,0x01,0x01,0x03
.byte	0xce,0x67,0x67,0xa9,	0x56,0x2b,0x2b,0x7d
.byte	0xe7,0xfe,0xfe,0x19,	0xb5,0xd7,0xd7,0x62
.byte	0x4d,0xab,0xab,0xe6,	0xec,0x76,0x76,0x9a
.byte	0x8f,0xca,0xca,0x45,	0x1f,0x82,0x82,0x9d
.byte	0x89,0xc9,0xc9,0x40,	0xfa,0x7d,0x7d,0x87
.byte	0xef,0xfa,0xfa,0x15,	0xb2,0x59,0x59,0xeb
.byte	0x8e,0x47,0x47,0xc9,	0xfb,0xf0,0xf0,0x0b
.byte	0x41,0xad,0xad,0xec,	0xb3,0xd4,0xd4,0x67
.byte	0x5f,0xa2,0xa2,0xfd,	0x45,0xaf,0xaf,0xea
.byte	0x23,0x9c,0x9c,0xbf,	0x53,0xa4,0xa4,0xf7
.byte	0xe4,0x72,0x72,0x96,	0x9b,0xc0,0xc0,0x5b
.byte	0x75,0xb7,0xb7,0xc2,	0xe1,0xfd,0xfd,0x1c
.byte	0x3d,0x93,0x93,0xae,	0x4c,0x26,0x26,0x6a
.byte	0x6c,0x36,0x36,0x5a,	0x7e,0x3f,0x3f,0x41
.byte	0xf5,0xf7,0xf7,0x02,	0x83,0xcc,0xcc,0x4f
.byte	0x68,0x34,0x34,0x5c,	0x51,0xa5,0xa5,0xf4
.byte	0xd1,0xe5,0xe5,0x34,	0xf9,0xf1,0xf1,0x08
.byte	0xe2,0x71,0x71,0x93,	0xab,0xd8,0xd8,0x73
.byte	0x62,0x31,0x31,0x53,	0x2a,0x15,0x15,0x3f
.byte	0x08,0x04,0x04,0x0c,	0x95,0xc7,0xc7,0x52
.byte	0x46,0x23,0x23,0x65,	0x9d,0xc3,0xc3,0x5e
.byte	0x30,0x18,0x18,0x28,	0x37,0x96,0x96,0xa1
.byte	0x0a,0x05,0x05,0x0f,	0x2f,0x9a,0x9a,0xb5
.byte	0x0e,0x07,0x07,0x09,	0x24,0x12,0x12,0x36
.byte	0x1b,0x80,0x80,0x9b,	0xdf,0xe2,0xe2,0x3d
.byte	0xcd,0xeb,0xeb,0x26,	0x4e,0x27,0x27,0x69
.byte	0x7f,0xb2,0xb2,0xcd,	0xea,0x75,0x75,0x9f
.byte	0x12,0x09,0x09,0x1b,	0x1d,0x83,0x83,0x9e
.byte	0x58,0x2c,0x2c,0x74,	0x34,0x1a,0x1a,0x2e
.byte	0x36,0x1b,0x1b,0x2d,	0xdc,0x6e,0x6e,0xb2
.byte	0xb4,0x5a,0x5a,0xee,	0x5b,0xa0,0xa0,0xfb
.byte	0xa4,0x52,0x52,0xf6,	0x76,0x3b,0x3b,0x4d
.byte	0xb7,0xd6,0xd6,0x61,	0x7d,0xb3,0xb3,0xce
.byte	0x52,0x29,0x29,0x7b,	0xdd,0xe3,0xe3,0x3e
.byte	0x5e,0x2f,0x2f,0x71,	0x13,0x84,0x84,0x97
.byte	0xa6,0x53,0x53,0xf5,	0xb9,0xd1,0xd1,0x68
.byte	0x00,0x00,0x00,0x00,	0xc1,0xed,0xed,0x2c
.byte	0x40,0x20,0x20,0x60,	0xe3,0xfc,0xfc,0x1f
.byte	0x79,0xb1,0xb1,0xc8,	0xb6,0x5b,0x5b,0xed
.byte	0xd4,0x6a,0x6a,0xbe,	0x8d,0xcb,0xcb,0x46
.byte	0x67,0xbe,0xbe,0xd9,	0x72,0x39,0x39,0x4b
.byte	0x94,0x4a,0x4a,0xde,	0x98,0x4c,0x4c,0xd4
.byte	0xb0,0x58,0x58,0xe8,	0x85,0xcf,0xcf,0x4a
.byte	0xbb,0xd0,0xd0,0x6b,	0xc5,0xef,0xef,0x2a
.byte	0x4f,0xaa,0xaa,0xe5,	0xed,0xfb,0xfb,0x16
.byte	0x86,0x43,0x43,0xc5,	0x9a,0x4d,0x4d,0xd7
.byte	0x66,0x33,0x33,0x55,	0x11,0x85,0x85,0x94
.byte	0x8a,0x45,0x45,0xcf,	0xe9,0xf9,0xf9,0x10
.byte	0x04,0x02,0x02,0x06,	0xfe,0x7f,0x7f,0x81
.byte	0xa0,0x50,0x50,0xf0,	0x78,0x3c,0x3c,0x44
.byte	0x25,0x9f,0x9f,0xba,	0x4b,0xa8,0xa8,0xe3
.byte	0xa2,0x51,0x51,0xf3,	0x5d,0xa3,0xa3,0xfe
.byte	0x80,0x40,0x40,0xc0,	0x05,0x8f,0x8f,0x8a
.byte	0x3f,0x92,0x92,0xad,	0x21,0x9d,0x9d,0xbc
.byte	0x70,0x38,0x38,0x48,	0xf1,0xf5,0xf5,0x04
.byte	0x63,0xbc,0xbc,0xdf,	0x77,0xb6,0xb6,0xc1
.byte	0xaf,0xda,0xda,0x75,	0x42,0x21,0x21,0x63
.byte	0x20,0x10,0x10,0x30,	0xe5,0xff,0xff,0x1a
.byte	0xfd,0xf3,0xf3,0x0e,	0xbf,0xd2,0xd2,0x6d
.byte	0x81,0xcd,0xcd,0x4c,	0x18,0x0c,0x0c,0x14
.byte	0x26,0x13,0x13,0x35,	0xc3,0xec,0xec,0x2f
.byte	0xbe,0x5f,0x5f,0xe1,	0x35,0x97,0x97,0xa2
.byte	0x88,0x44,0x44,0xcc,	0x2e,0x17,0x17,0x39
.byte	0x93,0xc4,0xc4,0x57,	0x55,0xa7,0xa7,0xf2
.byte	0xfc,0x7e,0x7e,0x82,	0x7a,0x3d,0x3d,0x47
.byte	0xc8,0x64,0x64,0xac,	0xba,0x5d,0x5d,0xe7
.byte	0x32,0x19,0x19,0x2b,	0xe6,0x73,0x73,0x95
.byte	0xc0,0x60,0x60,0xa0,	0x19,0x81,0x81,0x98
.byte	0x9e,0x4f,0x4f,0xd1,	0xa3,0xdc,0xdc,0x7f
.byte	0x44,0x22,0x22,0x66,	0x54,0x2a,0x2a,0x7e
.byte	0x3b,0x90,0x90,0xab,	0x0b,0x88,0x88,0x83
.byte	0x8c,0x46,0x46,0xca,	0xc7,0xee,0xee,0x29
.byte	0x6b,0xb8,0xb8,0xd3,	0x28,0x14,0x14,0x3c
.byte	0xa7,0xde,0xde,0x79,	0xbc,0x5e,0x5e,0xe2
.byte	0x16,0x0b,0x0b,0x1d,	0xad,0xdb,0xdb,0x76
.byte	0xdb,0xe0,0xe0,0x3b,	0x64,0x32,0x32,0x56
.byte	0x74,0x3a,0x3a,0x4e,	0x14,0x0a,0x0a,0x1e
.byte	0x92,0x49,0x49,0xdb,	0x0c,0x06,0x06,0x0a
.byte	0x48,0x24,0x24,0x6c,	0xb8,0x5c,0x5c,0xe4
.byte	0x9f,0xc2,0xc2,0x5d,	0xbd,0xd3,0xd3,0x6e
.byte	0x43,0xac,0xac,0xef,	0xc4,0x62,0x62,0xa6
.byte	0x39,0x91,0x91,0xa8,	0x31,0x95,0x95,0xa4
.byte	0xd3,0xe4,0xe4,0x37,	0xf2,0x79,0x79,0x8b
.byte	0xd5,0xe7,0xe7,0x32,	0x8b,0xc8,0xc8,0x43
.byte	0x6e,0x37,0x37,0x59,	0xda,0x6d,0x6d,0xb7
.byte	0x01,0x8d,0x8d,0x8c,	0xb1,0xd5,0xd5,0x64
.byte	0x9c,0x4e,0x4e,0xd2,	0x49,0xa9,0xa9,0xe0
.byte	0xd8,0x6c,0x6c,0xb4,	0xac,0x56,0x56,0xfa
.byte	0xf3,0xf4,0xf4,0x07,	0xcf,0xea,0xea,0x25
.byte	0xca,0x65,0x65,0xaf,	0xf4,0x7a,0x7a,0x8e
.byte	0x47,0xae,0xae,0xe9,	0x10,0x08,0x08,0x18
.byte	0x6f,0xba,0xba,0xd5,	0xf0,0x78,0x78,0x88
.byte	0x4a,0x25,0x25,0x6f,	0x5c,0x2e,0x2e,0x72
.byte	0x38,0x1c,0x1c,0x24,	0x57,0xa6,0xa6,0xf1
.byte	0x73,0xb4,0xb4,0xc7,	0x97,0xc6,0xc6,0x51
.byte	0xcb,0xe8,0xe8,0x23,	0xa1,0xdd,0xdd,0x7c
.byte	0xe8,0x74,0x74,0x9c,	0x3e,0x1f,0x1f,0x21
.byte	0x96,0x4b,0x4b,0xdd,	0x61,0xbd,0xbd,0xdc
.byte	0x0d,0x8b,0x8b,0x86,	0x0f,0x8a,0x8a,0x85
.byte	0xe0,0x70,0x70,0x90,	0x7c,0x3e,0x3e,0x42
.byte	0x71,0xb5,0xb5,0xc4,	0xcc,0x66,0x66,0xaa
.byte	0x90,0x48,0x48,0xd8,	0x06,0x03,0x03,0x05
.byte	0xf7,0xf6,0xf6,0x01,	0x1c,0x0e,0x0e,0x12
.byte	0xc2,0x61,0x61,0xa3,	0x6a,0x35,0x35,0x5f
.byte	0xae,0x57,0x57,0xf9,	0x69,0xb9,0xb9,0xd0
.byte	0x17,0x86,0x86,0x91,	0x99,0xc1,0xc1,0x58
.byte	0x3a,0x1d,0x1d,0x27,	0x27,0x9e,0x9e,0xb9
.byte	0xd9,0xe1,0xe1,0x38,	0xeb,0xf8,0xf8,0x13
.byte	0x2b,0x98,0x98,0xb3,	0x22,0x11,0x11,0x33
.byte	0xd2,0x69,0x69,0xbb,	0xa9,0xd9,0xd9,0x70
.byte	0x07,0x8e,0x8e,0x89,	0x33,0x94,0x94,0xa7
.byte	0x2d,0x9b,0x9b,0xb6,	0x3c,0x1e,0x1e,0x22
.byte	0x15,0x87,0x87,0x92,	0xc9,0xe9,0xe9,0x20
.byte	0x87,0xce,0xce,0x49,	0xaa,0x55,0x55,0xff
.byte	0x50,0x28,0x28,0x78,	0xa5,0xdf,0xdf,0x7a
.byte	0x03,0x8c,0x8c,0x8f,	0x59,0xa1,0xa1,0xf8
.byte	0x09,0x89,0x89,0x80,	0x1a,0x0d,0x0d,0x17
.byte	0x65,0xbf,0xbf,0xda,	0xd7,0xe6,0xe6,0x31
.byte	0x84,0x42,0x42,0xc6,	0xd0,0x68,0x68,0xb8
.byte	0x82,0x41,0x41,0xc3,	0x29,0x99,0x99,0xb0
.byte	0x5a,0x2d,0x2d,0x77,	0x1e,0x0f,0x0f,0x11
.byte	0x7b,0xb0,0xb0,0xcb,	0xa8,0x54,0x54,0xfc
.byte	0x6d,0xbb,0xbb,0xd6,	0x2c,0x16,0x16,0x3a

AES_Td:
.byte	0x51,0xf4,0xa7,0x50,	0x7e,0x41,0x65,0x53	# Td0
.byte	0x1a,0x17,0xa4,0xc3,	0x3a,0x27,0x5e,0x96
.byte	0x3b,0xab,0x6b,0xcb,	0x1f,0x9d,0x45,0xf1
.byte	0xac,0xfa,0x58,0xab,	0x4b,0xe3,0x03,0x93
.byte	0x20,0x30,0xfa,0x55,	0xad,0x76,0x6d,0xf6
.byte	0x88,0xcc,0x76,0x91,	0xf5,0x02,0x4c,0x25
.byte	0x4f,0xe5,0xd7,0xfc,	0xc5,0x2a,0xcb,0xd7
.byte	0x26,0x35,0x44,0x80,	0xb5,0x62,0xa3,0x8f
.byte	0xde,0xb1,0x5a,0x49,	0x25,0xba,0x1b,0x67
.byte	0x45,0xea,0x0e,0x98,	0x5d,0xfe,0xc0,0xe1
.byte	0xc3,0x2f,0x75,0x02,	0x81,0x4c,0xf0,0x12
.byte	0x8d,0x46,0x97,0xa3,	0x6b,0xd3,0xf9,0xc6
.byte	0x03,0x8f,0x5f,0xe7,	0x15,0x92,0x9c,0x95
.byte	0xbf,0x6d,0x7a,0xeb,	0x95,0x52,0x59,0xda
.byte	0xd4,0xbe,0x83,0x2d,	0x58,0x74,0x21,0xd3
.byte	0x49,0xe0,0x69,0x29,	0x8e,0xc9,0xc8,0x44
.byte	0x75,0xc2,0x89,0x6a,	0xf4,0x8e,0x79,0x78
.byte	0x99,0x58,0x3e,0x6b,	0x27,0xb9,0x71,0xdd
.byte	0xbe,0xe1,0x4f,0xb6,	0xf0,0x88,0xad,0x17
.byte	0xc9,0x20,0xac,0x66,	0x7d,0xce,0x3a,0xb4
.byte	0x63,0xdf,0x4a,0x18,	0xe5,0x1a,0x31,0x82
.byte	0x97,0x51,0x33,0x60,	0x62,0x53,0x7f,0x45
.byte	0xb1,0x64,0x77,0xe0,	0xbb,0x6b,0xae,0x84
.byte	0xfe,0x81,0xa0,0x1c,	0xf9,0x08,0x2b,0x94
.byte	0x70,0x48,0x68,0x58,	0x8f,0x45,0xfd,0x19
.byte	0x94,0xde,0x6c,0x87,	0x52,0x7b,0xf8,0xb7
.byte	0xab,0x73,0xd3,0x23,	0x72,0x4b,0x02,0xe2
.byte	0xe3,0x1f,0x8f,0x57,	0x66,0x55,0xab,0x2a
.byte	0xb2,0xeb,0x28,0x07,	0x2f,0xb5,0xc2,0x03
.byte	0x86,0xc5,0x7b,0x9a,	0xd3,0x37,0x08,0xa5
.byte	0x30,0x28,0x87,0xf2,	0x23,0xbf,0xa5,0xb2
.byte	0x02,0x03,0x6a,0xba,	0xed,0x16,0x82,0x5c
.byte	0x8a,0xcf,0x1c,0x2b,	0xa7,0x79,0xb4,0x92
.byte	0xf3,0x07,0xf2,0xf0,	0x4e,0x69,0xe2,0xa1
.byte	0x65,0xda,0xf4,0xcd,	0x06,0x05,0xbe,0xd5
.byte	0xd1,0x34,0x62,0x1f,	0xc4,0xa6,0xfe,0x8a
.byte	0x34,0x2e,0x53,0x9d,	0xa2,0xf3,0x55,0xa0
.byte	0x05,0x8a,0xe1,0x32,	0xa4,0xf6,0xeb,0x75
.byte	0x0b,0x83,0xec,0x39,	0x40,0x60,0xef,0xaa
.byte	0x5e,0x71,0x9f,0x06,	0xbd,0x6e,0x10,0x51
.byte	0x3e,0x21,0x8a,0xf9,	0x96,0xdd,0x06,0x3d
.byte	0xdd,0x3e,0x05,0xae,	0x4d,0xe6,0xbd,0x46
.byte	0x91,0x54,0x8d,0xb5,	0x71,0xc4,0x5d,0x05
.byte	0x04,0x06,0xd4,0x6f,	0x60,0x50,0x15,0xff
.byte	0x19,0x98,0xfb,0x24,	0xd6,0xbd,0xe9,0x97
.byte	0x89,0x40,0x43,0xcc,	0x67,0xd9,0x9e,0x77
.byte	0xb0,0xe8,0x42,0xbd,	0x07,0x89,0x8b,0x88
.byte	0xe7,0x19,0x5b,0x38,	0x79,0xc8,0xee,0xdb
.byte	0xa1,0x7c,0x0a,0x47,	0x7c,0x42,0x0f,0xe9
.byte	0xf8,0x84,0x1e,0xc9,	0x00,0x00,0x00,0x00
.byte	0x09,0x80,0x86,0x83,	0x32,0x2b,0xed,0x48
.byte	0x1e,0x11,0x70,0xac,	0x6c,0x5a,0x72,0x4e
.byte	0xfd,0x0e,0xff,0xfb,	0x0f,0x85,0x38,0x56
.byte	0x3d,0xae,0xd5,0x1e,	0x36,0x2d,0x39,0x27
.byte	0x0a,0x0f,0xd9,0x64,	0x68,0x5c,0xa6,0x21
.byte	0x9b,0x5b,0x54,0xd1,	0x24,0x36,0x2e,0x3a
.byte	0x0c,0x0a,0x67,0xb1,	0x93,0x57,0xe7,0x0f
.byte	0xb4,0xee,0x96,0xd2,	0x1b,0x9b,0x91,0x9e
.byte	0x80,0xc0,0xc5,0x4f,	0x61,0xdc,0x20,0xa2
.byte	0x5a,0x77,0x4b,0x69,	0x1c,0x12,0x1a,0x16
.byte	0xe2,0x93,0xba,0x0a,	0xc0,0xa0,0x2a,0xe5
.byte	0x3c,0x22,0xe0,0x43,	0x12,0x1b,0x17,0x1d
.byte	0x0e,0x09,0x0d,0x0b,	0xf2,0x8b,0xc7,0xad
.byte	0x2d,0xb6,0xa8,0xb9,	0x14,0x1e,0xa9,0xc8
.byte	0x57,0xf1,0x19,0x85,	0xaf,0x75,0x07,0x4c
.byte	0xee,0x99,0xdd,0xbb,	0xa3,0x7f,0x60,0xfd
.byte	0xf7,0x01,0x26,0x9f,	0x5c,0x72,0xf5,0xbc
.byte	0x44,0x66,0x3b,0xc5,	0x5b,0xfb,0x7e,0x34
.byte	0x8b,0x43,0x29,0x76,	0xcb,0x23,0xc6,0xdc
.byte	0xb6,0xed,0xfc,0x68,	0xb8,0xe4,0xf1,0x63
.byte	0xd7,0x31,0xdc,0xca,	0x42,0x63,0x85,0x10
.byte	0x13,0x97,0x22,0x40,	0x84,0xc6,0x11,0x20
.byte	0x85,0x4a,0x24,0x7d,	0xd2,0xbb,0x3d,0xf8
.byte	0xae,0xf9,0x32,0x11,	0xc7,0x29,0xa1,0x6d
.byte	0x1d,0x9e,0x2f,0x4b,	0xdc,0xb2,0x30,0xf3
.byte	0x0d,0x86,0x52,0xec,	0x77,0xc1,0xe3,0xd0
.byte	0x2b,0xb3,0x16,0x6c,	0xa9,0x70,0xb9,0x99
.byte	0x11,0x94,0x48,0xfa,	0x47,0xe9,0x64,0x22
.byte	0xa8,0xfc,0x8c,0xc4,	0xa0,0xf0,0x3f,0x1a
.byte	0x56,0x7d,0x2c,0xd8,	0x22,0x33,0x90,0xef
.byte	0x87,0x49,0x4e,0xc7,	0xd9,0x38,0xd1,0xc1
.byte	0x8c,0xca,0xa2,0xfe,	0x98,0xd4,0x0b,0x36
.byte	0xa6,0xf5,0x81,0xcf,	0xa5,0x7a,0xde,0x28
.byte	0xda,0xb7,0x8e,0x26,	0x3f,0xad,0xbf,0xa4
.byte	0x2c,0x3a,0x9d,0xe4,	0x50,0x78,0x92,0x0d
.byte	0x6a,0x5f,0xcc,0x9b,	0x54,0x7e,0x46,0x62
.byte	0xf6,0x8d,0x13,0xc2,	0x90,0xd8,0xb8,0xe8
.byte	0x2e,0x39,0xf7,0x5e,	0x82,0xc3,0xaf,0xf5
.byte	0x9f,0x5d,0x80,0xbe,	0x69,0xd0,0x93,0x7c
.byte	0x6f,0xd5,0x2d,0xa9,	0xcf,0x25,0x12,0xb3
.byte	0xc8,0xac,0x99,0x3b,	0x10,0x18,0x7d,0xa7
.byte	0xe8,0x9c,0x63,0x6e,	0xdb,0x3b,0xbb,0x7b
.byte	0xcd,0x26,0x78,0x09,	0x6e,0x59,0x18,0xf4
.byte	0xec,0x9a,0xb7,0x01,	0x83,0x4f,0x9a,0xa8
.byte	0xe6,0x95,0x6e,0x65,	0xaa,0xff,0xe6,0x7e
.byte	0x21,0xbc,0xcf,0x08,	0xef,0x15,0xe8,0xe6
.byte	0xba,0xe7,0x9b,0xd9,	0x4a,0x6f,0x36,0xce
.byte	0xea,0x9f,0x09,0xd4,	0x29,0xb0,0x7c,0xd6
.byte	0x31,0xa4,0xb2,0xaf,	0x2a,0x3f,0x23,0x31
.byte	0xc6,0xa5,0x94,0x30,	0x35,0xa2,0x66,0xc0
.byte	0x74,0x4e,0xbc,0x37,	0xfc,0x82,0xca,0xa6
.byte	0xe0,0x90,0xd0,0xb0,	0x33,0xa7,0xd8,0x15
.byte	0xf1,0x04,0x98,0x4a,	0x41,0xec,0xda,0xf7
.byte	0x7f,0xcd,0x50,0x0e,	0x17,0x91,0xf6,0x2f
.byte	0x76,0x4d,0xd6,0x8d,	0x43,0xef,0xb0,0x4d
.byte	0xcc,0xaa,0x4d,0x54,	0xe4,0x96,0x04,0xdf
.byte	0x9e,0xd1,0xb5,0xe3,	0x4c,0x6a,0x88,0x1b
.byte	0xc1,0x2c,0x1f,0xb8,	0x46,0x65,0x51,0x7f
.byte	0x9d,0x5e,0xea,0x04,	0x01,0x8c,0x35,0x5d
.byte	0xfa,0x87,0x74,0x73,	0xfb,0x0b,0x41,0x2e
.byte	0xb3,0x67,0x1d,0x5a,	0x92,0xdb,0xd2,0x52
.byte	0xe9,0x10,0x56,0x33,	0x6d,0xd6,0x47,0x13
.byte	0x9a,0xd7,0x61,0x8c,	0x37,0xa1,0x0c,0x7a
.byte	0x59,0xf8,0x14,0x8e,	0xeb,0x13,0x3c,0x89
.byte	0xce,0xa9,0x27,0xee,	0xb7,0x61,0xc9,0x35
.byte	0xe1,0x1c,0xe5,0xed,	0x7a,0x47,0xb1,0x3c
.byte	0x9c,0xd2,0xdf,0x59,	0x55,0xf2,0x73,0x3f
.byte	0x18,0x14,0xce,0x79,	0x73,0xc7,0x37,0xbf
.byte	0x53,0xf7,0xcd,0xea,	0x5f,0xfd,0xaa,0x5b
.byte	0xdf,0x3d,0x6f,0x14,	0x78,0x44,0xdb,0x86
.byte	0xca,0xaf,0xf3,0x81,	0xb9,0x68,0xc4,0x3e
.byte	0x38,0x24,0x34,0x2c,	0xc2,0xa3,0x40,0x5f
.byte	0x16,0x1d,0xc3,0x72,	0xbc,0xe2,0x25,0x0c
.byte	0x28,0x3c,0x49,0x8b,	0xff,0x0d,0x95,0x41
.byte	0x39,0xa8,0x01,0x71,	0x08,0x0c,0xb3,0xde
.byte	0xd8,0xb4,0xe4,0x9c,	0x64,0x56,0xc1,0x90
.byte	0x7b,0xcb,0x84,0x61,	0xd5,0x32,0xb6,0x70
.byte	0x48,0x6c,0x5c,0x74,	0xd0,0xb8,0x57,0x42

.byte	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38	# Td4
.byte	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
.byte	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87
.byte	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
.byte	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d
.byte	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
.byte	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2
.byte	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
.byte	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16
.byte	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
.byte	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda
.byte	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
.byte	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a
.byte	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
.byte	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02
.byte	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
.byte	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea
.byte	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
.byte	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85
.byte	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
.byte	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89
.byte	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
.byte	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20
.byte	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
.byte	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31
.byte	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
.byte	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d
.byte	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
.byte	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0
.byte	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
.byte	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26
.byte	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d

AES_Te4:
.byte	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5	# Te4
.byte	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
.byte	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0
.byte	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
.byte	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc
.byte	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
.byte	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a
.byte	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
.byte	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0
.byte	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
.byte	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b
.byte	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
.byte	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85
.byte	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
.byte	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5
.byte	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
.byte	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17
.byte	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
.byte	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88
.byte	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
.byte	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c
.byte	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
.byte	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9
.byte	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
.byte	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6
.byte	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
.byte	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e
.byte	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
.byte	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94
.byte	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
.byte	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68
.byte	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

.byte	0x01,0x00,0x00,0x00,	0x02,0x00,0x00,0x00	# rcon
.byte	0x04,0x00,0x00,0x00,	0x08,0x00,0x00,0x00
.byte	0x10,0x00,0x00,0x00,	0x20,0x00,0x00,0x00
.byte	0x40,0x00,0x00,0x00,	0x80,0x00,0x00,0x00
.byte	0x1B,0x00,0x00,0x00,	0x36,0x00,0x00,0x00
___

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/ge;

	# made-up _instructions, _xtr, _ins, _ror and _bias, cope
	# with byte order dependencies...
	if (/^\s+_/) {
	    s/(_[a-z]+\s+)(\$[0-9]+),([^,]+)(#.*)*$/$1$2,$2,$3/;

	    s/_xtr\s+(\$[0-9]+),(\$[0-9]+),([0-9]+(\-2)*)/
		sprintf("srl\t$1,$2,%d",$big_endian ?	eval($3)
					:		eval("24-$3"))/e or
	    s/_ins\s+(\$[0-9]+),(\$[0-9]+),([0-9]+)/
		sprintf("sll\t$1,$2,%d",$big_endian ?	eval($3)
					:		eval("24-$3"))/e or
	    s/_ins2\s+(\$[0-9]+),(\$[0-9]+),([0-9]+)/
		sprintf("ins\t$1,$2,%d,8",$big_endian ?	eval($3)
					:		eval("24-$3"))/e or
	    s/_ror\s+(\$[0-9]+),(\$[0-9]+),(\-?[0-9]+)/
		sprintf("srl\t$1,$2,%d",$big_endian ?	eval($3)
					:		eval("$3*-1"))/e or
	    s/_bias\s+(\$[0-9]+),(\$[0-9]+),([0-9]+)/
		sprintf("sll\t$1,$2,%d",$big_endian ?	eval($3)
					:		eval("($3-16)&31"))/e;

	    s/srl\s+(\$[0-9]+),(\$[0-9]+),\-([0-9]+)/
		sprintf("sll\t$1,$2,$3")/e				or
	    s/srl\s+(\$[0-9]+),(\$[0-9]+),0/
		sprintf("and\t$1,$2,0xff")/e				or
	    s/(sll\s+\$[0-9]+,\$[0-9]+,0)/#$1/;
	}

	# convert lwl/lwr and swr/swl to little-endian order
	if (!$big_endian && /^\s+[sl]w[lr]\s+/) {
	    s/([sl]wl.*)([0-9]+)\((\$[0-9]+)\)/
		sprintf("$1%d($3)",eval("$2-$2%4+($2%4-1)&3"))/e	or
	    s/([sl]wr.*)([0-9]+)\((\$[0-9]+)\)/
		sprintf("$1%d($3)",eval("$2-$2%4+($2%4+1)&3"))/e;
	}

	if (!$big_endian) {
	    s/(rotr\s+\$[0-9]+,\$[0-9]+),([0-9]+)/sprintf("$1,%d",32-$2)/e;
	    s/(ext\s+\$[0-9]+,\$[0-9]+),([0-9]+),8/sprintf("$1,%d,8",24-$2)/e;
	}

	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
