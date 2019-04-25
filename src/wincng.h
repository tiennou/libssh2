/*
 * Copyright (C) 2013-2015 Marc Hoersken <info@marc-hoersken.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

/* required for cross-compilation against the w64 mingw-runtime package */
#if defined(_WIN32_WINNT) && (_WIN32_WINNT < 0x0600)
#undef _WIN32_WINNT
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <bcrypt.h>

#define LIBSSH2_MD5 1

#define LIBSSH2_HMAC_RIPEMD 0
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 1
#define LIBSSH2_CAST 0
#define LIBSSH2_3DES 1

#define LIBSSH2_RSA 1
#define LIBSSH2_DSA 1
#define LIBSSH2_ECDSA 0
#define LIBSSH2_ED25519 0
/*******************************************************************/
/*
 * Windows CNG backend: Global context handles
 */

struct _libssh2_wincng_ctx {
    BCRYPT_ALG_HANDLE hAlgRNG;
    BCRYPT_ALG_HANDLE hAlgHashMD5;
    BCRYPT_ALG_HANDLE hAlgHashSHA1;
    BCRYPT_ALG_HANDLE hAlgHashSHA256;
    BCRYPT_ALG_HANDLE hAlgHashSHA384;
    BCRYPT_ALG_HANDLE hAlgHashSHA512;
    BCRYPT_ALG_HANDLE hAlgHmacMD5;
    BCRYPT_ALG_HANDLE hAlgHmacSHA1;
    BCRYPT_ALG_HANDLE hAlgHmacSHA256;
    BCRYPT_ALG_HANDLE hAlgHmacSHA512;
    BCRYPT_ALG_HANDLE hAlgRSA;
    BCRYPT_ALG_HANDLE hAlgDSA;
    BCRYPT_ALG_HANDLE hAlgAES_CBC;
    BCRYPT_ALG_HANDLE hAlgAES_ECB;
    BCRYPT_ALG_HANDLE hAlgRC4_NA;
    BCRYPT_ALG_HANDLE hAlg3DES_CBC;
};

struct _libssh2_wincng_ctx _libssh2_wincng;

/*******************************************************************/
/*
 * Windows CNG backend: Hash structure
 */

typedef struct __libssh2_wincng_hash_ctx {
    BCRYPT_HASH_HANDLE hHash;
    unsigned char *pbHashObject;
    unsigned long dwHashObject;
    unsigned long cbHash;
} _libssh2_wincng_hash_ctx;

#define libssh2_sha1_ctx _libssh2_wincng_hash_ctx
#define libssh2_sha256_ctx _libssh2_wincng_hash_ctx
#define libssh2_sha384_ctx _libssh2_wincng_hash_ctx
#define libssh2_sha512_ctx _libssh2_wincng_hash_ctx
#define libssh2_md5_ctx _libssh2_wincng_hash_ctx
#define libssh2_hmac_ctx _libssh2_wincng_hash_ctx

/*******************************************************************/
/*
 * Windows CNG backend: Key Context structure
 */

typedef struct __libssh2_wincng_key_ctx {
    BCRYPT_KEY_HANDLE hKey;
    unsigned char *pbKeyObject;
    unsigned long cbKeyObject;
} _libssh2_wincng_key_ctx;

#define libssh2_rsa_ctx _libssh2_wincng_key_ctx
#define libssh2_dsa_ctx _libssh2_wincng_key_ctx

/*******************************************************************/
/*
 * Windows CNG backend: Cipher Context structure
 */

struct _libssh2_wincng_cipher_ctx {
    BCRYPT_KEY_HANDLE hKey;
    unsigned char *pbKeyObject;
    unsigned char *pbIV;
    unsigned char *pbCtr;
    unsigned long dwKeyObject;
    unsigned long dwIV;
    unsigned long dwBlockLength;
    unsigned long dwCtrLength;
};

#define _libssh2_cipher_ctx struct _libssh2_wincng_cipher_ctx

/*
 * Windows CNG backend: Cipher Type structure
 */

struct _libssh2_wincng_cipher_type {
    BCRYPT_ALG_HANDLE *phAlg;
    unsigned long dwKeyLength;
    int useIV;      /* TODO: Convert to bool when a C89 compatible bool type
                       is defined */
    int ctrMode;
};

#define _libssh2_cipher_type(type) struct _libssh2_wincng_cipher_type type

#define _libssh2_cipher_aes256ctr { &_libssh2_wincng.hAlgAES_ECB, 32, 0, 1 }
#define _libssh2_cipher_aes192ctr { &_libssh2_wincng.hAlgAES_ECB, 24, 0, 1 }
#define _libssh2_cipher_aes128ctr { &_libssh2_wincng.hAlgAES_ECB, 16, 0, 1 }
#define _libssh2_cipher_aes256 { &_libssh2_wincng.hAlgAES_CBC, 32, 1, 0 }
#define _libssh2_cipher_aes192 { &_libssh2_wincng.hAlgAES_CBC, 24, 1, 0 }
#define _libssh2_cipher_aes128 { &_libssh2_wincng.hAlgAES_CBC, 16, 1, 0 }
#define _libssh2_cipher_arcfour { &_libssh2_wincng.hAlgRC4_NA, 16, 0, 0 }
#define _libssh2_cipher_3des { &_libssh2_wincng.hAlg3DES_CBC, 24, 1, 0 }

/*******************************************************************/
/*
 * Windows CNG backend: BigNumber Context
 */

#define _libssh2_bn_ctx int /* not used */

/*******************************************************************/
/*
 * Windows CNG backend: BigNumber structure
 */

struct _libssh2_wincng_bignum {
    unsigned char *bignum;
    size_t length;
};

#define _libssh2_bn struct _libssh2_wincng_bignum

/*
 * Windows CNG backend: Diffie-Hellman support
 */

#define _libssh2_dh_ctx struct _libssh2_wincng_bignum *
