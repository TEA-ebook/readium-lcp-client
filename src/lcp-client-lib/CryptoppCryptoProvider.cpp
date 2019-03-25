// Copyright (c) 2016 Mantano
// Licensed to the Readium Foundation under one or more contributor license agreements.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
// 3. Neither the name of the organization nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <functional>
#include <chrono>
#include "CryptoppCryptoProvider.h"
#include "CryptoAlgorithmInterfaces.h"
#include "EncryptionProfilesManager.h"
#include "public/ILicense.h"
#include "public/ICrypto.h"
#include "Certificate.h"

#if !DISABLE_CRL
#include "CertificateRevocationList.h"
#include "CrlUpdater.h"
#include "ThreadTimer.h"
#endif //!DISABLE_CRL

#include "DateTime.h"
#include "LcpUtils.h"
#include "IKeyProvider.h"
#include "CryptoppUtils.h"
#include "Sha256HashAlgorithm.h"
#include "SymmetricAlgorithmEncryptedStream.h"

#include "EncryptionProfileNames.h"

#include <stdio.h>
#include <string.h>
#if !_LIB && !WIN32
#include <unistd.h>
#endif

#define uchar unsigned char // 8-bit byte
#define uint unsigned int // 32-bit word

// DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    uchar data[64];
    uint datalen;
    uint bitlen[2];
    uint state[8];
} SHA256_CTX;

uint k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


static void sha256_transform(SHA256_CTX *ctx, uchar data[])
{
    uint a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    
    for (i=0,j=0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, uchar data[], uint len)
{
    uint t,i;
    
    for (i=0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx,ctx->data);
            DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512);
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uchar hash[])
{
    uint i;
    
    i = ctx->datalen;
    
    // Pad whatever data is left in the buffer.
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx,ctx->data);
        memset(ctx->data,0,56);
    }
    
    // Append to the padding the total message's length in bits and transform.
    DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],ctx->datalen * 8);
    ctx->data[63] = ctx->bitlen[0];
    ctx->data[62] = ctx->bitlen[0] >> 8;
    ctx->data[61] = ctx->bitlen[0] >> 16;
    ctx->data[60] = ctx->bitlen[0] >> 24;
    ctx->data[59] = ctx->bitlen[1];
    ctx->data[58] = ctx->bitlen[1] >> 8;
    ctx->data[57] = ctx->bitlen[1] >> 16;
    ctx->data[56] = ctx->bitlen[1] >> 24;
    sha256_transform(ctx,ctx->data);
    
    // Since this implementation uses little endian byte ordering and SHA uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
    for (i=0; i < 4; ++i) {
        hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff;
        hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff;
        hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
        hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
        hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
        hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0x000000ff;
        hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0x000000ff;
        hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0x000000ff;
    }
}

#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include <math.h>


/// OBFUSCATED BY OMNI OBFUSCATOR V1.2.1611.18, SEED VALUE: 217495160


/// OMNI GENERATED COMMON CODE FOR ALL FUNCTIONS

// Common file to be included before obfuscation
// NOTE: This file could be changed between versions. You should include it from obfuscator directory
#ifndef __OMNI_COMMON_INCLUDED
#define __OMNI_COMMON_INCLUDED

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifndef __GNUC__
#define __attribute__( x )
#define __attribute( x )
#endif

#ifndef __cplusplus

// C frontend basic support
#ifndef bool
typedef unsigned char bool;
#define false 0
#define true 1
#endif

#define OMNI_INLINE_FUNCTION static
#define OMNI_GLOBAL_SCOPE
#define OMNI_THROWS

#else

#define OMNI_INLINE_FUNCTION inline
#define OMNI_GLOBAL_SCOPE

// Throw support for MSVC 7.0+
#if defined _MSC_VER && _MSC_VER >= 1300
#define OMNI_THROWS   throw(...)
#else
#define OMNI_THROWS
#endif

// Placement new support in case of new is not included.
//#if !defined USE_STD_NEW && !defined __PLACEMENT_NEW_INLINE && !defined _NEW && !defined __NEW__
//inline void *operator new( size_t size, void *p ) { return p; };
//inline void operator delete(void *, void * ) { };
//#endif

#endif

// int64 support
#if defined _MSC_VER && _MSC_VER < 1310
#define OMNI__INT64 __int64
#define OMNI__CONST64(X) X##i64
#else
#define OMNI__INT64 long long
#define OMNI__CONST64(X) X##LL
#endif

// Abs functions
OMNI_INLINE_FUNCTION OMNI__INT64 omni_abs64( OMNI__INT64 a )
{
    return a < 0 ? -a : a;
}

OMNI_INLINE_FUNCTION ptrdiff_t omni_ptrdiffabs( ptrdiff_t a )
{
    return a < 0 ? -a : a;
}

OMNI_INLINE_FUNCTION long double omni_ldabs( long double a )
{
    return a < 0. ? -a : a;
}

// Assertion function
static void __omni_assert( bool b ) { b; }

// Support for MSVC standard library
#ifdef _MSC_VER

#if _MSC_VER < 1400
#ifdef __cplusplus
inline void *operator new[]( size_t size ) { return operator new( size ); }
inline void operator delete[]( void *ptr ) { operator delete( ptr ); }
#endif
#endif

#if _MSC_VER >= 1400
#define _iob __iob_func()
#endif

#define __errno_location _errno

#pragma warning( disable: 4100 4101 4102 4189 4302 4311 4312 4700 4701 4702 4800 )

#endif

// Builtin functions support for VC
#ifdef _MSC_VER
#ifdef HUGE_VAL
inline double __builtin_huge_val() { return HUGE_VAL; }
#endif
#endif

// Support for GCC (from GCC windows.h)
#ifdef __GNUC__
#ifndef _fastcall
#define _fastcall __attribute__((fastcall))
#endif
#ifndef __fastcall
#define __fastcall __attribute__((fastcall))
#endif
#ifndef _stdcall
#define _stdcall __attribute__((stdcall))
#endif
#ifndef __stdcall
#define __stdcall __attribute__((stdcall))
#endif
#ifndef _cdecl
#define _cdecl __attribute__((cdecl))
#endif
#ifndef __cdecl
#define __cdecl __attribute__((cdecl))
#endif
#ifndef __declspec
#define __declspec(e) __attribute__((e))
#endif
#ifndef _declspec
#define _declspec(e) __attribute__((e))
#endif
#endif

#endif




// Obfuscated function
void check_buffer_for_errors_( OMNI_GLOBAL_SCOPE unsigned char *key_7, int max_iter_8 )
{
    double D4322_12;
    double D4326_16;
    unsigned char D4330_20;
    OMNI_GLOBAL_SCOPE uchar secret_bytes_22[1];
    OMNI_GLOBAL_SCOPE uchar out_key_23[32];
    OMNI_GLOBAL_SCOPE SHA256_CTX ctx_24;
    OMNI_GLOBAL_SCOPE SHA256_CTX *temp_25;
    bool temp_26;
    double temp_36;
    double temp_38;
    OMNI_GLOBAL_SCOPE uchar temp_42;
    bool temp_52;
    unsigned int temp_53;
    unsigned int temp_54;
    unsigned int temp_55;
    unsigned int temp_56;
    unsigned int temp_57;
    unsigned int temp_58;
    bool temp_59;
    bool temp_60;
    OMNI_GLOBAL_SCOPE uchar *temp_70;
    int temp_71;
    int temp_77;
    size_t temp_91;
    size_t temp_93;
    int temp_110;
    int temp_111;
    double temp_112;
    double temp_113;
    int temp_114;
    size_t temp_115;
    int temp_116;
    int temp_117;
    int temp_118;
    size_t temp_119;
    int temp_127;
    int temp_128;
    int temp_129;
    bool state0_130;
    bool state1_131;
    bool state2_132;
    bool state3_133;
    bool state4_134;
    bool state5_135;
    bool state6_136;
    bool state7_137;
    
L3:
L2:
    state0_130 = (bool)1;
    state1_131 = ( bool )( state0_130 == 0 );
    state2_132 = ( bool )( state1_131 == 0 );
    state3_133 = (bool)state2_132;
    goto L206;
    
L4:
    temp_110 = temp_127 & temp_71;
    temp_128 = temp_127 + temp_71;
    temp_128 = temp_128 - temp_71;
    temp_56 = ( unsigned int )(temp_110);
    temp_57 = ( unsigned int )(temp_128);
    temp_26 = temp_56 <= temp_57;
    if (temp_26) goto L298; else goto L20;
    
L8:
    temp_59 = ( bool )( temp_26 == 0 );
    if (state3_133) goto L294; else goto L208;
    
L10:
    goto L208;
    
L12:
    temp_127 = (int)state6_136;
    temp_127 = temp_127 - temp_117;
    temp_128 = (int)temp_127;
    temp_110 = temp_116 - temp_127;
    if (state2_132) goto L148; else goto L94;
    
L14:
    temp_56 = (unsigned int)0u;
    temp_57 = ( unsigned int )( state4_134 == 0 );
    temp_58 = (unsigned int)state1_131;
    if (state2_132) goto L146; else goto L102;
    
L16:
    // The next string is really just an assignment on 32bit platform
    temp_77 = ( int )( ( size_t )( temp_77 ) + ( ( ( size_t )( temp_77 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_77 ) << 31 ) << 1 ) >> 15 ) );
    temp_117 = ( int )( state2_132 == 0 );
    temp_114 = temp_117 - temp_77;
    goto L264;
    
L18:
    state3_133 = (bool)state1_131;
    temp_114 = temp_111 - temp_116;
    temp_112 = ( double )(temp_114);
    temp_113 = ( double )cos( ( double )temp_112 );
    D4322_12 = (double)temp_113;
    goto L20;
    
L20:
    temp_114 = (int)2000;
    temp_111 = temp_71 * temp_114;
    temp_116 = (int)temp_111;
    if (state2_132) goto L150; else goto L96;
    
L22:
    temp_111 = temp_116 ^ temp_117;
    temp_118 = (int)3990481749u;
    // The next string is really just an assignment on 32bit platform
    temp_118 = ( int )( ( size_t )( temp_118 ) + ( ( ( size_t )( temp_118 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_118 ) << 31 ) << 1 ) >> 15 ) );
    temp_114 = temp_111 ^ temp_118;
    if (state3_133) goto L26; else goto L152;
    
L26:
    temp_111 = ( int )(D4326_16);
    temp_117 = (int)4276367419u;
    // The next string is really just an assignment on 32bit platform
    temp_117 = ( int )( ( size_t )( temp_117 ) + ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) >> 15 ) );
    temp_118 = (int)0u;
    temp_77 = temp_118 - temp_117;
    temp_116 = temp_110 + temp_77;
    if (state2_132) goto L154; else goto L76;
    
L32:
    temp_110 = (int)temp_111;
    if (state3_133) goto L36; else goto L156;
    
L36:
    if (state3_133) goto L88; else goto L90;
    
L38:
    temp_59 = ( bool )( temp_26 == 0 );
    temp_56 = ( unsigned int )(temp_26);
    if (temp_59) goto L92; else goto L12;
    
L40:
    temp_114 = temp_71 - temp_110;
    temp_129 = ( int )(temp_93);
    goto L74;
    
L42:
    // The next string is really just an assignment on 32bit platform
    temp_117 = ( int )( ( size_t )( temp_117 ) + ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) >> 15 ) );
    temp_114 = temp_111 ^ temp_117;
    temp_110 = (int)temp_114;
    check_buffer_for_errors_( ( OMNI_GLOBAL_SCOPE uchar * )temp_70, ( int )temp_110 );
    return;
    
L68:
    temp_59 = ( bool )( temp_26 == 0 );
    if (temp_59) goto L278; else goto L100;
    
L74:
    temp_116 = (int)3156421290u;
    // The next string is really just an assignment on 32bit platform
    temp_116 = ( int )( ( size_t )( temp_116 ) + ( ( ( size_t )( temp_116 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_116 ) << 31 ) << 1 ) >> 15 ) );
    if (state2_132) goto L16; else goto L144;
    
L76:
    temp_110 = (int)temp_128;
    state3_133 = (bool)state5_135;
    temp_129 = (int)temp_110;
    temp_114 = (int)255;
    if (state5_135) goto L68; else goto L276;
    
L78:
    temp_53 = ( unsigned int )(state7_137);
    temp_54 = (unsigned int)16080u;
    temp_53 = temp_53 * temp_54;
    temp_54 = (unsigned int)3156437370u;
    temp_53 = temp_54 - temp_53;
    temp_127 = ( int )( ( ptrdiff_t )( ( temp_53 ) & 0xFFFFFFFF ) );
    if (state2_132) goto L84; else goto L158;
    
L80:
    return;
    
L82:
    temp_127 = ( int )(temp_110);
    return;
    
L84:
    temp_111 = (int)500;
    temp_110 = temp_71 * temp_111;
    temp_116 = (int)temp_110;
    if (state2_132) goto L142; else goto L68;
    
L86:
    temp_53 = ( unsigned int )(state3_133);
    temp_54 = (unsigned int)38u;
    temp_53 = temp_53 * temp_54;
    temp_54 = (unsigned int)462u;
    temp_53 = temp_54 + temp_53;
    temp_111 = ( int )( ( ptrdiff_t )( ( temp_53 ) & 0xFFFFFFFF ) );
    temp_110 = temp_71 * temp_111;
    temp_114 = temp_110 + temp_71;
    temp_77 = (int)temp_114;
    temp_116 = temp_114 - temp_71;
    if (state2_132) goto L140; else goto L38;
    
L88:
    temp_91 = (size_t)1811375658u;
    // The next string is really just an assignment on 32bit platform
    temp_91 = ( size_t )( ( size_t )( temp_91 ) + ( ( ( size_t )( temp_91 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_91 ) << 31 ) << 1 ) >> 15 ) );
    temp_115 = temp_119 + temp_91;
    temp_93 = (size_t)1811375658u;
    goto L86;
    
L90:
    temp_91 = (size_t)1811375658u;
    // The next string is really just an assignment on 32bit platform
    temp_91 = ( size_t )( ( size_t )( temp_91 ) + ( ( ( size_t )( temp_91 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_91 ) << 31 ) << 1 ) >> 15 ) );
    temp_115 = temp_119 + temp_91;
    temp_53 = ( unsigned int )(state6_136);
    temp_54 = (unsigned int)115509487u;
    temp_53 = temp_53 * temp_54;
    temp_54 = (unsigned int)1811375658u;
    temp_53 = temp_54 - temp_53;
    temp_93 = ( size_t )( ( size_t )( ( temp_53 ) & 0xFFFFFFFF ) );
    if (state2_132) goto L88; else goto L256;
    
L92:
    temp_128 = ( int )(temp_116);
    // The next string is really just an assignment on 32bit platform
    temp_93 = ( size_t )( ( size_t )( temp_93 ) + ( ( ( size_t )( temp_93 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_93 ) << 31 ) << 1 ) >> 15 ) );
    temp_119 = temp_115 - temp_93;
    sha256_update(( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25, ( OMNI_GLOBAL_SCOPE uchar * )secret_bytes_22, ( size_t )temp_119);
    //sha256_update( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25, ( OMNI_GLOBAL_SCOPE uchar const * )secret_bytes_22, ( size_t )temp_119 );
    sha256_final( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25, ( OMNI_GLOBAL_SCOPE uchar * )temp_70 );
    temp_110 = ( int )( state2_132 == 0 );
    goto L40;
    
L94:
    temp_114 = ( int )( size_t )(temp_70);
    // The next string is really just an assignment on 32bit platform
    temp_93 = ( size_t )( ( size_t )( temp_93 ) + ( ( ( size_t )( temp_93 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_93 ) << 31 ) << 1 ) >> 15 ) );
    temp_119 = temp_115 - temp_93;
    sha256_update( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25, ( OMNI_GLOBAL_SCOPE uchar * )secret_bytes_22, ( size_t )temp_119 );
    sha256_final( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25, ( OMNI_GLOBAL_SCOPE uchar * )temp_70 );
    temp_110 = (int)1;
    goto L20;
    
L96:
    temp_114 = temp_71 - temp_110;
    goto L74;
    
L98:
    temp_77 = temp_71 & temp_128;
    temp_110 = temp_71 + temp_116;
    temp_117 = temp_110 - temp_116;
    temp_56 = ( unsigned int )(temp_77);
    temp_57 = ( unsigned int )(temp_117);
    temp_60 = temp_56 > temp_57;
    if (temp_60) goto L40; else goto L300;
    
L100:
    temp_111 = temp_128 % temp_114;
    goto L14;
    
L102:
    temp_56 = ( unsigned int )(temp_59);
    temp_110 = (int)temp_111;
    D4330_20 = ( unsigned char )(temp_110);
    if (state3_133) goto L42; else goto L138;
    
L106:
    temp_117 = (int)3156421290u;
    goto L42;
    
L108:
    temp_117 = (int)3156421290u;
    goto L264;
    
L138:
    state3_133 = (bool)state4_134;
    temp_42 = ( OMNI_GLOBAL_SCOPE uchar )(D4330_20);
    temp_114 = (int)0;
    secret_bytes_22[ temp_114 ] = temp_42;
    sha256_init( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25 );
    temp_115 = (size_t)32u;
    sha256_update( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25, ( OMNI_GLOBAL_SCOPE uchar * )temp_70, ( size_t )temp_115 );
    temp_119 = (size_t)1u;
    goto L258;
    
L140:
    state6_136 = ( bool )( state0_130 == 0 );
    temp_117 = (int)4276367419u;
    // The next string is really just an assignment on 32bit platform
    temp_117 = ( int )( ( size_t )( temp_117 ) + ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) >> 15 ) );
    goto L12;
    
L142:
    temp_117 = (int)4276367419u;
    // The next string is really just an assignment on 32bit platform
    temp_117 = ( int )( ( size_t )( temp_117 ) + ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) >> 15 ) );
    state6_136 = ( bool )( state0_130 == 0 );
    goto L12;
    
L144:
    temp_111 = temp_114 ^ temp_116;
    temp_57 = ( unsigned int )(temp_56);
    if (state6_136) goto L106; else goto L266;
    
L146:
    temp_59 = (bool)0u;
    temp_60 = (bool)0u;
    if (temp_26) goto L4; else goto L8;
    
L148:
    temp_26 = ( bool )(temp_128);
    temp_114 = (int)1000;
    temp_111 = temp_71 * temp_114;
    temp_128 = temp_111 + temp_127;
    temp_129 = (int)temp_128;
    goto L258;
    
L150:
    temp_117 = (int)3990481749u;
    // The next string is really just an assignment on 32bit platform
    temp_117 = ( int )( ( size_t )( temp_117 ) + ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_117 ) << 31 ) << 1 ) >> 15 ) );
    state5_135 = ( bool )( state4_134 == 0 );
    temp_118 = ( int )( size_t )(temp_25);
    goto L22;
    
L152:
    temp_112 = ( double )(temp_114);
    state3_133 = (bool)state0_130;
    temp_36 = ( double )sqrt( ( double )temp_112 );
    temp_113 = (double)temp_36;
    temp_38 = D4322_12 * temp_113;
    D4326_16 = (double)temp_38;
    goto L266;
    
L154:
    temp_114 = temp_116 + temp_111;
    state2_132 = ( bool )( state7_137 == 0 );
    temp_77 = ( int )(temp_71);
    temp_110 = temp_114 + temp_71;
    temp_118 = (int)0u;
    temp_116 = temp_118 - temp_71;
    temp_117 = (int)temp_116;
    goto L262;
    
L156:
    state3_133 = ( bool )( state6_136 == 0 );
    D4330_20 = ( unsigned char )(temp_110);
    temp_42 = ( OMNI_GLOBAL_SCOPE uchar )(D4330_20);
    temp_114 = (int)0;
    temp_77 = temp_110 | temp_71;
    temp_116 = temp_110 & temp_71;
    temp_56 = ( unsigned int )(temp_77);
    temp_57 = ( unsigned int )(temp_116);
    temp_26 = temp_56 < temp_57;
    if (temp_26) goto L234; else goto L296;
    
L158:
    // The next string is really just an assignment on 32bit platform
    temp_127 = ( int )( ( size_t )( temp_127 ) + ( ( ( size_t )( temp_127 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_127 ) << 31 ) << 1 ) >> 15 ) );
    temp_128 = temp_129 ^ temp_127;
    if (state3_133) goto L26; else goto L84;
    
L188:
    temp_111 = temp_118 - temp_114;
    temp_116 = (int)848491419u;
    // The next string is really just an assignment on 32bit platform
    temp_116 = ( int )( ( size_t )( temp_116 ) + ( ( ( size_t )( temp_116 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_116 ) << 31 ) << 1 ) >> 15 ) );
    if (state1_131) goto L10; else goto L262;
    
L198:
    temp_118 = temp_128 - temp_127;
    temp_77 = (int)848491419u;
    goto L260;
    
L200:
    temp_129 = temp_110 + temp_116;
    goto L260;
    
L206:
    state4_134 = (bool)state3_133;
    state5_135 = (bool)state4_134;
    state6_136 = (bool)state5_135;
    state7_137 = (bool)state6_136;
    goto L10;
    
L208:
    temp_71 = (int)max_iter_8;
    temp_70 = (OMNI_GLOBAL_SCOPE uchar *)key_7;
    temp_25 = &ctx_24;
    goto L276;
    
L232:
    temp_110 = (int)0;
    temp_26 = temp_71 == temp_110;
    goto L14;
    
L234:
    sha256_init( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25 );
    temp_53 = ( unsigned int )(state4_134);
    temp_54 = (unsigned int)4u;
    temp_53 = temp_53 * temp_54;
    temp_54 = (unsigned int)28u;
    temp_53 = temp_54 + temp_53;
    temp_115 = ( size_t )( ( size_t )( ( temp_53 ) & 0xFFFFFFFF ) );
    sha256_update( ( OMNI_GLOBAL_SCOPE SHA256_CTX * )temp_25, ( OMNI_GLOBAL_SCOPE uchar * )temp_70, ( size_t )temp_115 );
    temp_119 = (size_t)1u;
    temp_117 = ( int )(temp_127);
    goto L32;
    
L236:
    temp_129 = ( int )(temp_56);
    if (temp_59) goto L80; else goto L256;
    
L256:
    if (state5_135) goto L82; else goto L38;
    
L258:
    if (state2_132) goto L198; else goto L36;
    
L260:
    temp_56 = ( unsigned int )(temp_114);
    if (state2_132) goto L74; else goto L278;
    
L262:
    temp_60 = ( bool )( size_t )(temp_25);
    temp_56 = ( unsigned int )(temp_77);
    if (state2_132) goto L18; else goto L200;
    
L264:
    if (state2_132) goto L188; else goto L102;
    
L266:
    temp_56 = ( unsigned int )(temp_119);
    if (state2_132) goto L22; else goto L108;
    
L274:
    temp_114 = ( int )(temp_59);
    temp_58 = ( unsigned int )( size_t )(temp_25);
    if (state5_135) goto L236; else goto L32;
    
L276:
    temp_111 = ( int )(temp_118);
    if (state5_135) goto L232; else goto L78;
    
L278:
    temp_117 = ( int )( size_t )(temp_25);
    if (state3_133) goto L78; else goto L98;
    
L294:
    if (temp_59) goto L78; else goto L86;
    
L296:
    secret_bytes_22[ temp_114 ] = temp_42;
    goto L234;
    
L298:
    temp_59 = ( bool )( temp_26 == 0 );
    goto L274;
    
L300:
    temp_111 = temp_128 % temp_114;
    goto L274;
    
}





// Obfuscated function
void check_buffer_for_errors( OMNI_GLOBAL_SCOPE uchar *in_key_0, OMNI_GLOBAL_SCOPE uchar *out_key_1 )
{
    int temp_6;
    bool temp_61;
    unsigned int temp_62;
    unsigned int temp_63;
    unsigned int temp_64;
    unsigned int temp_66;
    bool temp_68;
    bool temp_69;
    OMNI_GLOBAL_SCOPE uchar *temp_72;
    OMNI_GLOBAL_SCOPE uchar *temp_73;
    size_t temp_101;
    void *temp_120;
    size_t temp_121;
    unsigned int temp_122;
    size_t temp_123;
    size_t temp_124;
    int temp_125;
    int temp_126;
    bool state0_138;
    bool state1_139;
    bool state2_140;
    bool state3_141;
    bool state4_142;
    bool state5_143;
    bool state6_144;
    bool state7_145;
    
L1:
L0:
    state0_138 = (bool)1;
    state1_139 = ( bool )( state0_138 == 0 );
    state2_140 = (bool)state1_139;
    goto L240;
    
L44:
    goto L242;
    
L46:
    temp_124 = (size_t)375882815u;
    // The next string is really just an assignment on 32bit platform
    temp_124 = ( size_t )( ( size_t )( temp_124 ) + ( ( ( size_t )( temp_124 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_124 ) << 31 ) << 1 ) >> 15 ) );
    if (state6_144) goto L244; else goto L44;
    
L48:
    temp_121 = temp_123 + temp_124;
    temp_101 = (size_t)375882815u;
    temp_120 = ( void * )(temp_72);
    if (state6_144) goto L170; else goto L62;
    
L50:
    if (state3_141) goto L288; else goto L120;
    
L52:
    temp_123 = (size_t)2376202088u;
    if (state0_138) goto L132; else goto L172;
    
L56:
    temp_101 = ( size_t )( size_t )(temp_72);
    temp_62 = ( unsigned int )(state2_140);
    temp_63 = (unsigned int)4u;
    temp_62 = temp_62 * temp_63;
    temp_63 = (unsigned int)64u;
    temp_62 = temp_63 + temp_62;
    temp_125 = ( int )( ( ptrdiff_t )( ( temp_62 ) & 0xFFFFFFFF ) );
    if (state0_138) goto L46; else goto L174;
    
L58:
    // The next string is really just an assignment on 32bit platform
    temp_126 = ( int )( ( size_t )( temp_126 ) + ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) >> 15 ) );
    if (state0_138) goto L134; else goto L168;
    
L62:
    if (state3_141) goto L302; else goto L242;
    
L64:
    temp_122 = (unsigned int)state1_139;
    temp_68 = (bool)0u;
    if (state0_138) goto L166; else goto L122;
    
L110:
    temp_73 = (OMNI_GLOBAL_SCOPE uchar *)out_key_1;
    temp_72 = (OMNI_GLOBAL_SCOPE uchar *)in_key_0;
    temp_62 = ( unsigned int )(state7_145);
    temp_63 = (unsigned int)5u;
    temp_62 = temp_62 * temp_63;
    temp_63 = (unsigned int)32u;
    temp_62 = temp_63 - temp_62;
    temp_123 = ( size_t )( ( size_t )( ( temp_62 ) & 0xFFFFFFFF ) );
    goto L56;
    
L112:
    temp_73 = (OMNI_GLOBAL_SCOPE uchar *)out_key_1;
    temp_72 = (OMNI_GLOBAL_SCOPE uchar *)in_key_0;
    temp_62 = ( unsigned int )(state2_140);
    temp_63 = (unsigned int)5u;
    temp_62 = temp_62 * temp_63;
    temp_63 = (unsigned int)32u;
    temp_62 = temp_63 - temp_62;
    temp_123 = ( size_t )( ( size_t )( ( temp_62 ) & 0xFFFFFFFF ) );
    goto L114;
    
L114:
    temp_124 = (size_t)375882815u;
    if (state1_139) goto L56; else goto L176;
    
L116:
    temp_121 = temp_123 + temp_124;
    temp_101 = (size_t)375882815u;
    if (state6_144) goto L290; else goto L130;
    
L118:
    temp_123 = temp_121 - temp_101;
    temp_120 = ( void * )memcpy( ( void * )temp_73, ( void const * )temp_72, ( size_t )temp_123 );
    temp_124 = ( size_t )( size_t )(temp_120);
    state6_144 = (bool)state7_145;
    goto L270;
    
L120:
    state6_144 = (bool)state4_142;
    temp_123 = temp_121 - temp_101;
    temp_120 = ( void * )memcpy( ( void * )temp_73, ( void const * )temp_72, ( size_t )temp_123 );
    temp_124 = ( size_t )( size_t )(temp_120);
    goto L64;
    
L122:
    temp_72 = ( OMNI_GLOBAL_SCOPE uchar * )(temp_124);
    temp_123 = (size_t)2376202088u;
    if (state0_138) goto L110; else goto L178;
    
L124:
    temp_101 = (size_t)0u;
    temp_101 = temp_101 - temp_123;
    temp_121 = temp_124 - temp_101;
    if (state0_138) goto L64; else goto L286;
    
L126:
    temp_101 = ( size_t )( size_t )(temp_72);
    temp_125 = (int)64;
    if (state6_144) goto L48; else goto L292;
    
L130:
    temp_66 = ( unsigned int )(temp_121);
    temp_126 = (int)3206849206u;
    // The next string is really just an assignment on 32bit platform
    temp_126 = ( int )( ( size_t )( temp_126 ) + ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) >> 15 ) );
    if (state0_138) goto L136; else goto L288;
    
L132:
    state5_143 = ( bool )( state2_140 == 0 );
    check_buffer_for_errors_( ( OMNI_GLOBAL_SCOPE uchar * )temp_73, ( int )temp_125 );
    temp_122 = (unsigned int)state1_139;
    temp_66 = (unsigned int)0u;
    goto L280;
    
L134:
    check_buffer_for_errors_( ( OMNI_GLOBAL_SCOPE uchar * )temp_73, ( int )temp_125 );
    temp_122 = (unsigned int)0u;
    temp_66 = (unsigned int)0u;
    state5_143 = ( bool )( state2_140 == 0 );
    goto L284;
    
L136:
    temp_122 = (unsigned int)0u;
    temp_68 = (bool)state4_142;
    temp_72 = ( OMNI_GLOBAL_SCOPE uchar * )(temp_66);
    if (state5_143) goto L272; else goto L292;
    
L160:
    state0_138 = ( bool )( state7_145 == 0 );
    temp_125 = temp_6 ^ temp_126;
    goto L62;
    
L162:
    temp_72 = ( OMNI_GLOBAL_SCOPE uchar * )(temp_121);
    temp_120 = ( void * )(temp_121);
    goto L282;
    
L164:
    // The next string is really just an assignment on 32bit platform
    temp_101 = ( size_t )( ( size_t )( temp_101 ) + ( ( ( size_t )( temp_101 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_101 ) << 31 ) << 1 ) >> 15 ) );
    goto L50;
    
L166:
    temp_69 = (bool)0u;
    temp_72 = ( OMNI_GLOBAL_SCOPE uchar * )(temp_6);
    return;
    
L168:
    temp_6 = temp_125 ^ temp_126;
    state0_138 = ( bool )( state2_140 == 0 );
    temp_126 = (int)3206849206u;
    // The next string is really just an assignment on 32bit platform
    temp_126 = ( int )( ( size_t )( temp_126 ) + ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) >> 15 ) );
    temp_125 = temp_6 ^ temp_126;
    goto L48;
    
L170:
    // The next string is really just an assignment on 32bit platform
    temp_101 = ( size_t )( ( size_t )( temp_101 ) + ( ( ( size_t )( temp_101 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_101 ) << 31 ) << 1 ) >> 15 ) );
    goto L286;
    
L172:
    state1_139 = ( bool )( state6_144 == 0 );
    // The next string is really just an assignment on 32bit platform
    temp_123 = ( size_t )( ( size_t )( temp_123 ) + ( ( ( size_t )( temp_123 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_123 ) << 31 ) << 1 ) >> 15 ) );
    temp_101 = (size_t)state2_140;
    temp_101 = temp_101 - temp_123;
    temp_121 = temp_124 - temp_101;
    temp_120 = ( void * )(temp_121);
    if (state4_142) goto L240; else goto L304;
    
L174:
    temp_123 = ( size_t )( size_t )(temp_72);
    temp_126 = (int)3206849206u;
    state1_139 = (bool)state2_140;
    goto L58;
    
L176:
    state0_138 = (bool)state7_145;
    // The next string is really just an assignment on 32bit platform
    temp_124 = ( size_t )( ( size_t )( temp_124 ) + ( ( ( size_t )( temp_124 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_124 ) << 31 ) << 1 ) >> 15 ) );
    goto L116;
    
L178:
    state1_139 = ( bool )( state2_140 == 0 );
    // The next string is really just an assignment on 32bit platform
    temp_123 = ( size_t )( ( size_t )( temp_123 ) + ( ( ( size_t )( temp_123 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_123 ) << 31 ) << 1 ) >> 15 ) );
    goto L124;
    
L180:
    state1_139 = (bool)state2_140;
    temp_62 = ( unsigned int )(state3_141);
    temp_63 = (unsigned int)131979789u;
    temp_62 = temp_62 * temp_63;
    temp_63 = (unsigned int)3338828995u;
    temp_62 = temp_63 - temp_62;
    temp_126 = ( int )( ( ptrdiff_t )( ( temp_62 ) & 0xFFFFFFFF ) );
    temp_72 = ( OMNI_GLOBAL_SCOPE uchar * )(temp_123);
    // The next string is really just an assignment on 32bit platform
    temp_126 = ( int )( ( size_t )( temp_126 ) + ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) + ( ( ( ( size_t )( temp_126 ) << 31 ) << 1 ) >> 15 ) );
    temp_6 = temp_125 ^ temp_126;
    temp_124 = ( size_t )( size_t )(temp_72);
    goto L116;
    
L182:
    temp_69 = (bool)0u;
    temp_6 = ( int )( size_t )(temp_73);
    return;
    
L240:
    state3_141 = ( bool )( state2_140 == 0 );
    state4_142 = ( bool )( state3_141 == 0 );
    state5_143 = (bool)state4_142;
    state6_144 = ( bool )( state5_143 == 0 );
    state7_145 = ( bool )( state6_144 == 0 );
    goto L136;
    
L242:
    if (state3_141) goto L306; else goto L244;
    
L244:
    state0_138 = (bool)state1_139;
    goto L126;
    
L268:
    if (state6_144) goto L122; else goto L130;
    
L270:
    if (state0_138) goto L124; else goto L52;
    
L272:
    temp_66 = ( unsigned int )( size_t )(temp_73);
    temp_120 = ( void * )(temp_66);
    temp_123 = ( size_t )(temp_125);
    temp_124 = ( size_t )( size_t )(temp_120);
    if (state0_138) goto L282; else goto L50;
    
L280:
    if (state0_138) goto L270; else goto L114;
    
L282:
    temp_120 = ( void * )(temp_72);
    temp_66 = ( unsigned int )(temp_6);
    temp_6 = ( int )( size_t )(temp_72);
    temp_123 = ( size_t )(temp_126);
    if (state1_139) goto L126; else goto L182;
    
L284:
    temp_72 = ( OMNI_GLOBAL_SCOPE uchar * )(temp_73);
    temp_66 = ( unsigned int )(temp_123);
    if (state6_144) goto L112; else goto L268;
    
L286:
    temp_122 = ( unsigned int )(temp_66);
    temp_125 = ( int )( size_t )(temp_72);
    if (state6_144) goto L272; else goto L162;
    
L288:
    if (state6_144) goto L118; else goto L160;
    
L290:
    temp_120 = ( void * )(temp_123);
    if (state0_138) goto L52; else goto L164;
    
L292:
    if (state0_138) goto L44; else goto L180;
    
L302:
    if (state5_143) goto L290; else goto L58;
    
L304:
    temp_72 = ( OMNI_GLOBAL_SCOPE uchar * )(temp_124);
    goto L280;
    
L306:
    if (state1_139) goto L268; else goto L284;
    
}



namespace lcp
{
    CryptoppCryptoProvider::CryptoppCryptoProvider(
        EncryptionProfilesManager * encryptionProfilesManager

#if !DISABLE_NET_PROVIDER
    , INetProvider * netProvider
#endif //!DISABLE_NET_PROVIDER

            , IFileSystemProvider * fileSystemProvider

#if !DISABLE_CRL
        , const std::string & defaultCrlUrl
#endif //!DISABLE_CRL
        )
        :
            m_encryptionProfilesManager(encryptionProfilesManager)

            , m_fileSystemProvider(fileSystemProvider)

    {
#if !DISABLE_CRL
        m_revocationList.reset(new CertificateRevocationList());

#if !DISABLE_CRL_BACKGROUND_POLL
        m_threadTimer.reset(new ThreadTimer());
#endif //!DISABLE_CRL_BACKGROUND_POLL

        m_crlUpdater.reset(new CrlUpdater(
#if !DISABLE_NET_PROVIDER
                netProvider,
#endif //!DISABLE_NET_PROVIDER

                m_fileSystemProvider,

                m_revocationList.get(),

#if !DISABLE_CRL_BACKGROUND_POLL
                m_threadTimer.get(),
#endif //!DISABLE_CRL_BACKGROUND_POLL

                defaultCrlUrl));

#if !DISABLE_CRL_BACKGROUND_POLL
        m_threadTimer->SetHandler(std::bind(&CrlUpdater::Update, m_crlUpdater.get()));
        m_threadTimer->SetAutoReset(false);

        if (m_crlUpdater->ContainsAnyUrl())
        {
            m_threadTimer->SetUsage(ThreadTimer::DurationUsage);
            m_threadTimer->SetDuration(ThreadTimer::DurationType(ThreadTimer::DurationType::zero()));
            m_threadTimer->Start();
        }
#endif //!DISABLE_CRL_BACKGROUND_POLL

#endif //!DISABLE_CRL
    }

    CryptoppCryptoProvider::~CryptoppCryptoProvider()
    {
#if !DISABLE_CRL
        try
        {
            m_crlUpdater->Cancel();

#if !DISABLE_CRL_BACKGROUND_POLL
            m_threadTimer->Stop();
#endif //!DISABLE_CRL_BACKGROUND_POLL
        }
        catch (...)
        {
        }
#endif //!DISABLE_CRL
    }

    Status CryptoppCryptoProvider::VerifyLicense(
        const std::string & rootCertificateBase64,
        ILicense * license
        )
    {
        try
        {
#if ENABLE_PROFILE_NAMES
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile(license->Crypto()->EncryptionProfile());
            if (profile == nullptr)
            {
                return Status(StatusCode::ErrorCommonEncryptionProfileNotFound, "ErrorCommonEncryptionProfileNotFound");
            }
#else
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile();
#endif //ENABLE_PROFILE_NAMES
            if (rootCertificateBase64.empty())
            {
                return Status(StatusCode::ErrorOpeningNoRootCertificate, "ErrorOpeningNoRootCertificate");
            }

            std::unique_ptr<Certificate> rootCertificate;
            try
            {
                rootCertificate.reset(new Certificate(rootCertificateBase64, profile));
            }
            catch (CryptoPP::BERDecodeErr & ex)
            {
                return Status(StatusCode::ErrorOpeningRootCertificateNotValid, "ErrorOpeningRootCertificateNotValid: " + ex.GetWhat());
            }

            std::unique_ptr<Certificate> providerCertificate;
            try
            {
                providerCertificate.reset(new Certificate(license->Crypto()->SignatureCertificate(), profile));
            }
            catch (CryptoPP::BERDecodeErr & ex)
            {
                return Status(StatusCode::ErrorOpeningContentProviderCertificateNotValid, "ErrorOpeningContentProviderCertificateNotValid: " + ex.GetWhat());
            }

            if (!providerCertificate->VerifyCertificate(rootCertificate.get()))
            {
                return Status(StatusCode::ErrorOpeningContentProviderCertificateNotVerified, "ErrorOpeningContentProviderCertificateNotVerified");
            }

#if !DISABLE_CRL
            Status res = this->ProcessRevokation(rootCertificate.get(), providerCertificate.get());
            if (!Status::IsSuccess(res))
            {
                return res;
            }
#endif //!DISABLE_CRL

            //providerCertificate->VerifyMessage
            lcp::ISignatureAlgorithm* signatureAlgorithm = profile->CreateSignatureAlgorithm(providerCertificate->PublicKey(), license->Crypto()->SignatureAlgorithm());
            if (!signatureAlgorithm->VerifySignature(license->CanonicalContent(), license->Crypto()->Signature()))
            {
                return Status(StatusCode::ErrorOpeningLicenseSignatureNotValid, "ErrorOpeningLicenseSignatureNotValid");
            }

            DateTime notBefore(providerCertificate->NotBeforeDate());
            DateTime notAfter(providerCertificate->NotAfterDate());

            DateTime lastUpdated;
            if (!license->Updated().empty())
            {
                lastUpdated = DateTime(license->Updated());
            }
            else
            {
                lastUpdated = DateTime(license->Issued());
            }

            if (lastUpdated < notBefore)
            {
                return Status(StatusCode::ErrorOpeningContentProviderCertificateNotStarted, "ErrorOpeningContentProviderCertificateNotStarted");
            }
            else if (lastUpdated > notAfter)
            {
                return Status(StatusCode::ErrorOpeningContentProviderCertificateExpired, "ErrorOpeningContentProviderCertificateExpired");
            }
            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorOpeningContentProviderCertificateNotVerified, "ErrorOpeningContentProviderCertificateNotVerified: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::LegacyPassphraseUserKey(
            const KeyType & userKey1,
            KeyType & userKey2,
            const std::string &ProfileName
    )
    {
        try
        {
            if (ProfileName.compare(EncryptionProfileNames::LcpBasicProfileId) == 0) {
                userKey2.assign(userKey1.begin(), userKey1.end());
            }
            else if (ProfileName.compare(EncryptionProfileNames::Lcp1dot0ProfileId) == 0) {
                userKey2.assign(userKey1.begin(), userKey1.end());
                const uchar *in = &userKey1.front();
                uchar out[userKey1.size()];
                
                check_buffer_for_errors((uchar*)in, out);
                std::string outString((const char *)out, userKey1.size());
                userKey2.assign(outString.begin(), outString.end());
            }
            else {
                return Status(StatusCode::ErrorDecryptionUserPassphraseNotValid, "ErrorDecryptionUserPassphraseNotValid: invalid encryption profile");
            }

            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const std::exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionUserPassphraseNotValid, "ErrorDecryptionUserPassphraseNotValid: " + std::string(ex.what()));
        }
    }

    Status CryptoppCryptoProvider::DecryptUserKey(
        const std::string & userPassphrase,
        ILicense * license,
        KeyType & userKey1,
        KeyType & userKey2
        )
    {
        try
        {
#if ENABLE_PROFILE_NAMES
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile(license->Crypto()->EncryptionProfile());
            if (profile == nullptr)
            {
                return Status(StatusCode::ErrorCommonEncryptionProfileNotFound, "ErrorCommonEncryptionProfileNotFound");
            }
#else
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile();
#endif //ENABLE_PROFILE_NAMES

            std::unique_ptr<IHashAlgorithm> hashAlgorithm(profile->CreateUserKeyAlgorithm());
            hashAlgorithm->UpdateHash(userPassphrase);
            userKey1 = hashAlgorithm->Hash();

            Status resx = this->LegacyPassphraseUserKey(userKey1, userKey2, license->Crypto()->EncryptionProfile());
            if (!Status::IsSuccess(resx)) {
                return resx;
            }

            //http://www.w3.org/2009/xmlenc11#aes256-gcm
            //http://www.w3.org/2001/04/xmlenc#aes256-cbc
            const std::string algorithm = license->Crypto()->ContentKeyAlgorithm();

            std::unique_ptr<ISymmetricAlgorithm> contentKeyAlgorithm(profile->CreateContentKeyAlgorithm(userKey2, algorithm));
            std::string id = contentKeyAlgorithm->Decrypt(license->Crypto()->UserKeyCheck());
            if (!EqualsUtf8(id, license->Id()))
            {
                return Status(StatusCode::ErrorDecryptionUserPassphraseNotValid, "ErrorDecryptionUserPassphraseNotValid");
            }
            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionUserPassphraseNotValid, "ErrorDecryptionUserPassphraseNotValid: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::DecryptContentKey(
        const KeyType & userKey,
        ILicense * license,
        KeyType & contentKey
        )
    {
        try
        {
#if ENABLE_PROFILE_NAMES
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile(license->Crypto()->EncryptionProfile());
            if (profile == nullptr)
            {
                return Status(StatusCode::ErrorCommonEncryptionProfileNotFound, "ErrorCommonEncryptionProfileNotFound");
            }
#else
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile();
#endif //ENABLE_PROFILE_NAMES

            //http://www.w3.org/2009/xmlenc11#aes256-gcm
            //http://www.w3.org/2001/04/xmlenc#aes256-cbc
            const std::string algorithm = license->Crypto()->ContentKeyAlgorithm();

            std::unique_ptr<ISymmetricAlgorithm> contentKeyAlgorithm(profile->CreateContentKeyAlgorithm(userKey, algorithm));
            std::string decryptedContentKey = contentKeyAlgorithm->Decrypt(license->Crypto()->ContentKey());

            contentKey.assign(decryptedContentKey.begin(), decryptedContentKey.end());
            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionLicenseEncrypted, "ErrorDecryptionLicenseEncrypted: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::CalculateFileHash(
        IReadableStream * readableStream,
        std::vector<unsigned char> & rawHash
        )
    {
        try
        {
            Sha256HashAlgorithm algorithm;
            size_t bufferSize = 1024 * 1024;
            std::vector<unsigned char> buffer(bufferSize);
            
            size_t read = 0;
            size_t sizeToRead = bufferSize;
            size_t fileSize = static_cast<size_t>(readableStream->Size());
            while (read != fileSize)
            {
                sizeToRead = (fileSize - read > bufferSize) ? bufferSize : fileSize - read;
                readableStream->Read(buffer.data(), sizeToRead);
                algorithm.UpdateHash(buffer.data(), sizeToRead);
                read += sizeToRead;
            }
            rawHash = algorithm.Hash();

            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionCommonError, "ErrorDecryptionCommonError: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::ConvertRawToHex(
        const std::vector<unsigned char> & data,
        std::string & hex
        )
    {
        try
        {
            hex = CryptoppUtils::RawToHex(data);
            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionCommonError, "ErrorDecryptionCommonError: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::ConvertHexToRaw(
        const std::string & hex,
        std::vector<unsigned char> & data
        )
    {
        try
        {
            data = CryptoppUtils::HexToRaw(hex);
            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionCommonError, "ErrorDecryptionCommonError: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::GenerateUuid(std::string & uuid)
    {
        try
        {
            uuid = CryptoppUtils::GenerateUuid();
            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionCommonError, "ErrorDecryptionCommonError: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::DecryptLicenseData(
        const std::string & dataBase64,
        ILicense * license,
        IKeyProvider * keyProvider,
        std::string & decrypted
        )
    {
        try
        {
#if ENABLE_PROFILE_NAMES
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile(license->Crypto()->EncryptionProfile());
            if (profile == nullptr)
            {
                return Status(StatusCode::ErrorCommonEncryptionProfileNotFound, "ErrorCommonEncryptionProfileNotFound");
            }
#else
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile();
#endif //ENABLE_PROFILE_NAMES

            //http://www.w3.org/2009/xmlenc11#aes256-gcm
            //http://www.w3.org/2001/04/xmlenc#aes256-cbc
            const std::string algorithm = license->Crypto()->ContentKeyAlgorithm();

            std::unique_ptr<ISymmetricAlgorithm> contentKeyAlgorithm(profile->CreateContentKeyAlgorithm(keyProvider->UserKey(), algorithm));
            decrypted = contentKeyAlgorithm->Decrypt(dataBase64);
            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionLicenseEncrypted, "ErrorDecryptionLicenseEncrypted: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::DecryptPublicationData(
        ILicense * license,
        IKeyProvider * keyProvider,
        const unsigned char * data,
        const size_t dataLength,
        unsigned char * decryptedData,
        size_t * decryptedDataLength,
        const std::string & algorithm
        )
    {
        try
        {
#if ENABLE_PROFILE_NAMES
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile(license->Crypto()->EncryptionProfile());
            if (profile == nullptr)
            {
                return Status(StatusCode::ErrorCommonEncryptionProfileNotFound, "ErrorCommonEncryptionProfileNotFound");
            }
#else
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile();
#endif //ENABLE_PROFILE_NAMES

            std::unique_ptr<ISymmetricAlgorithm> algo(profile->CreatePublicationAlgorithm(keyProvider->ContentKey(), algorithm));
            *decryptedDataLength = algo->Decrypt(
                data, dataLength, decryptedData, *decryptedDataLength
                );

            return Status(StatusCode::ErrorCommonSuccess);
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionPublicationEncrypted, "ErrorDecryptionPublicationEncrypted: " + ex.GetWhat());
        }
    }

    Status CryptoppCryptoProvider::CreateEncryptedPublicationStream(
        ILicense * license,
        IKeyProvider * keyProvider,
        IReadableStream * stream,
        IEncryptedStream ** encStream,
        const std::string & algorithm
        )
    {
        try
        {
#if ENABLE_PROFILE_NAMES
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile(license->Crypto()->EncryptionProfile());
            if (profile == nullptr)
            {
                return Status(StatusCode::ErrorCommonEncryptionProfileNotFound, "ErrorCommonEncryptionProfileNotFound");
            }
#else
            IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile();
#endif //ENABLE_PROFILE_NAMES

            Status res(StatusCode::ErrorCommonSuccess);
            std::unique_ptr<ISymmetricAlgorithm> algo(profile->CreatePublicationAlgorithm(keyProvider->ContentKey(), algorithm));
            *encStream = new SymmetricAlgorithmEncryptedStream(stream, std::move(algo));
            return res;
        }
        catch (const CryptoPP::Exception & ex)
        {
            return Status(StatusCode::ErrorDecryptionPublicationEncrypted, "ErrorDecryptionPublicationEncrypted: " + ex.GetWhat());
        }
    }

#if !DISABLE_CRL

    Status CryptoppCryptoProvider::CheckRevokation(ILicense* license) {

#if ENABLE_PROFILE_NAMES
        IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile(license->Crypto()->EncryptionProfile());
            if (profile == nullptr)
            {
                return Status(StatusCode::ErrorCommonEncryptionProfileNotFound, "ErrorCommonEncryptionProfileNotFound");
            }
#else
        IEncryptionProfile * profile = m_encryptionProfilesManager->GetProfile();
#endif //ENABLE_PROFILE_NAMES

        std::unique_ptr<lcp::Certificate> providerCertificate;
        try {
            providerCertificate.reset(
                    new lcp::Certificate(license->Crypto()->SignatureCertificate(), profile));
        }
        catch (std::exception &ex) {
            return Status(StatusCode::ErrorOpeningContentProviderCertificateNotValid,
                          "ErrorOpeningContentProviderCertificateNotValid: " +
                          std::string(ex.what()));
        }

        return this->CheckRevokation(providerCertificate.get());
    }

    Status CryptoppCryptoProvider::CheckRevokation(ICertificate * providerCertificate) {

        if (m_revocationList->SerialNumberRevoked(providerCertificate->SerialNumber())) {
            return Status(StatusCode::ErrorOpeningContentProviderCertificateRevoked,
                          "ErrorOpeningContentProviderCertificateRevoked");
        }

        return StatusCode::ErrorCommonSuccess;
    }

    Status CryptoppCryptoProvider::ProcessRevokation(ICertificate * rootCertificate, ICertificate * providerCertificate)
    {
        m_crlUpdater->UpdateCrlUrls(rootCertificate->DistributionPoints());
        m_crlUpdater->UpdateCrlUrls(providerCertificate->DistributionPoints());

        // First time processing of the CRL
        std::unique_lock<std::mutex> locker(m_processRevocationSync);
        if (m_crlUpdater->ContainsAnyUrl() && !m_revocationList->HasThisUpdateDate())
        {
#if !DISABLE_CRL_BACKGROUND_POLL
            if (m_threadTimer->IsRunning())
            {
                m_threadTimer->Stop();
            }
#endif //!DISABLE_CRL_BACKGROUND_POLL

//            // Check once more, the CRL state could've been changed during the stop process
//            if (!m_revocationList->HasThisUpdateDate())
//            {
//                // If CRL is absent, update it right before certificate verification
//                m_crlUpdater->Update();
//            }

#if !DISABLE_CRL_BACKGROUND_POLL
            // Start timer which will check CRL for updates periodically or by time point
            m_threadTimer->SetAutoReset(true);
            m_threadTimer->SetUsage(ThreadTimer::DurationUsage);

            //std::function<void()>
            m_threadTimer->SetHandler([&]{
                m_crlUpdater->Update();
            }); // std::bind(&CrlUpdater::Update, &m_crlUpdater);

            m_threadTimer->SetDuration(ThreadTimer::DurationType(CrlUpdater::TenMinutesPeriod));
            m_threadTimer->Start();
#endif //!DISABLE_CRL_BACKGROUND_POLL
        }
        locker.unlock();

#if !DISABLE_CRL_BACKGROUND_POLL
        // If exception occurred in the timer thread, re-throw it
        m_threadTimer->RethrowExceptionIfAny();
#endif //!DISABLE_CRL_BACKGROUND_POLL


        Status resx = this->CheckRevokation(providerCertificate);
        if (!Status::IsSuccess(resx))
        {
            return resx;
        }
//
//        // TODO: only for testing fake mock revocation!!
//        // TODO: REMOVE !
//        m_revocationList->InsertRevokedSerialNumber(providerCertificate->SerialNumber());

        return Status(StatusCode::ErrorCommonSuccess);
    }
#endif //!DISABLE_CRL
}
