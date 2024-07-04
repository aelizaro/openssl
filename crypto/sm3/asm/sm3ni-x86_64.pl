#! /usr/bin/env perl
# Copyright 2024-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# This module implements support for Intel SM3 instructions

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

# Need a meaningful check here instead of $avx
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([2-9]\.[0-9]+)/) {
	$avx = ($1>=2.19) + ($1>=2.22);
}

if (!$avx && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
	   `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
	$avx = ($1>=2.09) + ($1>=2.10);
}

if (!$avx && `$ENV{CC} -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
	$avx = ($2>=3.0) + ($2>3.0);
}

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

@_3args=$win64?	("%rcx","%rdx","%r8") :	# Win64 order
        ("%rdi","%rsi","%rdx");	# Unix order

if ($avx>0) { #<<<
# Create 4 x 32-bit new words of message schedule W[] using SM3-NI ISA
sub sm3msg() {
my ($W03_00, $W07_04, $W11_08, $W15_12, $W19_16, $T1,$T2)=@_;
$T3 = $W19_16
# Q: is it correct to write `3*4`?
# Q: parameters order?
$code.=<<___;
    vpalignr        $T3, $W11_08, $W07_04, `3*4`
    vpsrldq         $T1, $W15_12, \$4
    vsm3msg1        $T3, $T1, $W03_00
    vpalignr        $T1, $W07_04, $W03_00, `3*4`
    vpalignr        $T2, $W15_12, $W11_08, `2*4`
    vsm3msg2        $T3, $T1, $T2
___
}

# Performs 4 rounds of SM3 algorithm
#   - consumes 4 words of message schedule W[]
#   - updates SM3 state registers: ABEF and CDGH
sub sm3rounds4() {
# Q: the last parameter of vsm3rnds2 syntax?
my ($ABEF, $CDGH, $W03_00, $W07_04, $T1,$R)=@_;
$code.=<<___;
    vpunpcklqdq     $T1, $W03_00, $W07_04
    vsm3rnds2       $CDGH, $ABEF, $T1, $R
    vpunpckhqdq     $T1, $W03_00, $W07_04
    vsm3rnds2       $ABEF, $CDGH, $T1, ($R + 2)
___
}

# void ossl_hwsm3_block_data_order(SM3_CTX *c, const void *p, size_t num)
#
# input: $ctx SM3 context
#        $p  pointer to the data
#        $num number of blocks
#
{ my ($ctx,$p,$num) = @_3args;

# Q: changing order in mov for AT&T?
# Q: syntax vmovdqu         16($ctx), %xmm7 ?
# Q: vpshufd parameters order?
# Q: vpxor + q? for xmm registers?
# Q: shuffle mask?
$code.=<<___;
align 16
SHUFF_MASK:
    .byte 0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4, 0x11, 0x10, 0x9, 0x8, 0x15, 0x14, 0x13, 0x12
    # db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

.globl	ossl_hwsm3_block_data_order
.type	ossl_hwsm3_block_data_order,\@function,3
.align	16
ossl_hwsm3_block_data_order:
    movsxd   %edx, %rdx

    vmovdqu         ($ctx), %xmm6
    vmovdqu         16($ctx), %xmm7

    vpshufd         $0x1B, %xmm6, %xmm0
    vpshufd         $0x1B, %xmm7, %xmm1
    vpunpckhqdq     %xmm0, %xmm1, %xmm6
    vpunpcklqdq     %xmm0, %xmm1, %xmm7
    vpsrld          $9, %xmm7, %xmm2
    vpslld          $23, %xmm7, %xmm3
    vpxorq          %xmm3, %xmm2, %xmm1
    vpsrld          $19, %xmm7, %xmm4
    vpslld          $13, %xmm7, %xmm5
    vpxorq          %xmm0, %xmm4, %xmm5
    vpblendd        $0x3, %xmm0, %xmm1, %xmm7

    vmovdqa         SHUFF_MASK(%rip), %xmm12

align 32
.block_loop:
    vmovdqa         %xmm6, %xmm10
    vmovdqa         %xmm7, %xmm11

    ;; prepare W[0..15] - read and shuffle the data
    vmovdqu         ($p) %xmm2
    vmovdqu         16($p), %xmm3
    vmovdqu         32($p), %xmm4
    vmovdqu         48($p), %xmm5
    vpshufb         %xmm12, %xmm2, %xmm2                            # xmm2 = W03 W02 W01 W00
    vpshufb         %xmm12, %xmm3, %xmm3                            # xmm3 = W07 W06 W05 W04
    vpshufb         %xmm12, %xmm4, %xmm4                            # xmm4 = W11 W10 W09 W08
    vpshufb         %xmm12, %xmm5, %xmm5                            # xmm5 = W15 W14 W13 W12

    @{[sm3msg %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, 0]}
    # SM3MSG          %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W19 W18 W17 W16
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, $0

    vmovdqa         %xmm8, %xmm2
    @{[sm3msg %xmm3, %xmm4, %xmm5, %xmm2, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, 4]}
    # SM3MSG          %xmm3, %xmm4, %xmm5, %xmm2, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W23 W22 W21 W20
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, $4

    vmovdqa         %xmm8, %xmm3
    @{[sm3msg %xmm4, %xmm5, %xmm2, %xmm3, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, 8]}
    # SM3MSG          %xmm4, %xmm5, %xmm2, %xmm3, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W27 W26 W25 W24
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, $8

    vmovdqa         %xmm8, %xmm4
    @{[sm3msg %xmm5, %xmm2, %xmm3, %xmm4, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, 12]}
    # SM3MSG          %xmm5, %xmm2, %xmm3, %xmm4, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W31 W30 W29 W28
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, $12

    vmovdqa         %xmm8, %xmm5
    @{[sm3msg %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, 16]}
    # SM3MSG          %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W35 W34 W33 W32
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, $16

    vmovdqa         %xmm8, %xmm2
    @{[sm3msg %xmm3, %xmm4, %xmm5, %xmm2, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, 20]}
    # SM3MSG          %xmm3, %xmm4, %xmm5, %xmm2, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W39 W38 W37 W36
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, $20

    vmovdqa         %xmm8, %xmm3
    @{[sm3msg %xmm4, %xmm5, %xmm2, %xmm3, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, 24]}
    # SM3MSG          %xmm4, %xmm5, %xmm2, %xmm3, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W43 W42 W41 W40
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, $24

    vmovdqa         %xmm8, %xmm4
    @{[sm3msg %xmm5, %xmm2, %xmm3, %xmm4, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, 28]}
    # SM3MSG          %xmm5, %xmm2, %xmm3, %xmm4, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W47 W46 W45 W44
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, $28

    vmovdqa         %xmm8, %xmm5
    @{[sm3msg %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, 32]}
    # SM3MSG          %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W51 W50 W49 W48
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, $32

    vmovdqa         %xmm8, %xmm2
    @{[sm3msg %xmm3, %xmm4, %xmm5, %xmm2, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, 36]}
    # SM3MSG          %xmm3, %xmm4, %xmm5, %xmm2, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W55 W54 W53 W52
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, $36

    vmovdqa         %xmm8, %xmm3
    @{[sm3msg %xmm4, %xmm5, %xmm2, %xmm3, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, 40]}
    # SM3MSG          %xmm4, %xmm5, %xmm2, %xmm3, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W59 W58 W57 W56
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, $40

    vmovdqa         %xmm8, %xmm4
    @{[sm3msg %xmm5, %xmm2, %xmm3, %xmm4, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, 44]}
    # SM3MSG          %xmm5, %xmm2, %xmm3, %xmm4, %xmm8, %xmm9, %xmm1        # ?? xmm8 = W63 W62 W61 W60
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, %44

    vmovdqa         %xmm8, %xmm5
    @{[sm3msg %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1]}
    @{[sm3rounds4 %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, 48]}
    # SM3MSG          %xmm2, %xmm3, %xmm4, %xmm5, %xmm8, %xmm9, %xmm1       # ?? xmm8 = W67 W66 W65 W64
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm2, %xmm3, %xmm1, $48

    vmovdqa         %xmm8, %xmm2
    @{[sm3rounds4 %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, 52]}
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm3, %xmm4, %xmm1, $52

    @{[sm3rounds4 %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, 56]}
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm4, %xmm5, %xmm1, $56

    @{[sm3rounds4 %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, 60]}
    # SM3ROUNDS4      %xmm6, %xmm7, %xmm5, %xmm2, %xmm1, $60

    # update hash value
    vpxor           %xmm10, %xmm6, %xmm6
    vpxor           %xmm11, %xmm7, %xmm7
    addq            $64, ($p)
    dec             $num
    jnz             .block_loop

    # store the hash value back in memory
    vpslld          $9, %xmm7, %xmm2
    vpsrld          $23, %xmm7, %xmm3
    vpxor           %xmm3, %xmm2, %xmm1        # xmm1 = xmm2 ^ xmm3 = ROL32(CDGH, 9)
    vpslld          $19, %xmm7, %xmm4
    vpsrld          $13, %xmm7, %xmm5
    vpxor           %xmm5, %xmm4, %xmm0         # xmm0 = xmm2 ^ xmm3 = ROL32(CDGH, 19)
    vpblendd        $0x3, %xmm0, %xmm1, %xmm7   # xmm7 = ROL32(C, 9) ROL32(D, 9) ROL32(G, 19) ROL32(H, 19)
    vpshufd         $0x1B, %xmm6, %xmm0,        # xmm0 = F E B A
    vpshufd         $0x1B, %xmm7, %xmm1         # xmm1 = H G D C

    vpunpcklqdq     %xmm0, %xmm1, %xmm6        # xmm6 = D C B A
    vpunpckhqdq     %xmm0, %xmm1, %xmm7           # xmm7 = H G F E

    vmovdqu         %xmm6, ($ctx)
    vmovdqu         %xmm7, 16($ctx)

   ret
___
}
}