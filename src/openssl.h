/* Copyright (C) 2009, 2010 Simon Josefsson
 * Copyright (C) 2006, 2007 The Written Word, Inc.  All rights reserved.
 *
 * Author: Simon Josefsson
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

#include <openssl/opensslconf.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_MD5
#include <openssl/md5.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(LIBRESSL_VERSION_NUMBER)
# define HAVE_OPAQUE_STRUCTS 1
# define OPAQUE_ADDR(ptr) ptr
# define OPAQUE_PTR(ptr) *ptr
# define OPAQUE_DEF(ptr) ptr *
#else
# define OPAQUE_ADDR(ptr) &ptr
# define OPAQUE_PTR(ptr) ptr
# define OPAQUE_DEF(ptr) ptr
#endif

#ifdef OPENSSL_NO_RSA
# define LIBSSH2_RSA 0
#else
# define LIBSSH2_RSA 1
#endif

#ifdef OPENSSL_NO_DSA
# define LIBSSH2_DSA 0
#else
# define LIBSSH2_DSA 1
#endif

#ifdef OPENSSL_NO_ECDSA
# define LIBSSH2_ECDSA 0
#else
# define LIBSSH2_ECDSA 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && \
!defined(LIBRESSL_VERSION_NUMBER)
# define LIBSSH2_ED25519 1
#else
# define LIBSSH2_ED25519 0
#endif


#ifdef OPENSSL_NO_MD5
# define LIBSSH2_MD5 0
#else
# define LIBSSH2_MD5 1
#endif

#ifdef OPENSSL_NO_RIPEMD
# define LIBSSH2_HMAC_RIPEMD 0
#else
# define LIBSSH2_HMAC_RIPEMD 1
#endif

#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#if OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_AES)
# define LIBSSH2_AES_CTR 1
# define LIBSSH2_AES 1
#else
# define LIBSSH2_AES_CTR 0
# define LIBSSH2_AES 0
#endif

#ifdef OPENSSL_NO_BF
# define LIBSSH2_BLOWFISH 0
#else
# define LIBSSH2_BLOWFISH 1
#endif

#ifdef OPENSSL_NO_RC4
# define LIBSSH2_RC4 0
#else
# define LIBSSH2_RC4 1
#endif

#ifdef OPENSSL_NO_CAST
# define LIBSSH2_CAST 0
#else
# define LIBSSH2_CAST 1
#endif

#ifdef OPENSSL_NO_DES
# define LIBSSH2_3DES 0
#else
# define LIBSSH2_3DES 1
#endif

#define libssh2_crypto_errcode unsigned long

#define libssh2_sha1_ctx OPAQUE_DEF(EVP_MD_CTX)
#define libssh2_sha256_ctx OPAQUE_DEF(EVP_MD_CTX)
#define libssh2_sha384_ctx OPAQUE_DEF(EVP_MD_CTX)
#define libssh2_sha512_ctx OPAQUE_DEF(EVP_MD_CTX)
#define libssh2_md5_ctx OPAQUE_DEF(EVP_MD_CTX)
#define libssh2_hmac_ctx OPAQUE_DEF(HMAC_CTX)

#define libssh2_rsa_ctx RSA
#define libssh2_dsa_ctx DSA

#if LIBSSH2_ECDSA
#define libssh2_ecdsa_ctx EC_KEY
#define _libssh2_ecdsa_free(ecdsactx) EC_KEY_free(ecdsactx)
#define _libssh2_ec_key EC_KEY

typedef enum {
    LIBSSH2_EC_CURVE_NISTP256 = NID_X9_62_prime256v1,
    LIBSSH2_EC_CURVE_NISTP384 = NID_secp384r1,
    LIBSSH2_EC_CURVE_NISTP521 = NID_secp521r1
}
libssh2_curve_type;
#else
#define _libssh2_ec_key void
#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519

typedef struct {
    EVP_PKEY *public_key;
    EVP_PKEY *private_key;
} libssh2_curve25519_keys;

#define libssh2_ed25519_ctx libssh2_curve25519_keys
#define libssh2_x25519_ctx libssh2_curve25519_keys

#define _libssh2_ed25519_new_ctx() calloc(1, sizeof(libssh2_ed25519_ctx))
#define _libssh2_ed25519_free(ctx) do { \
 if(ctx) { \
  if(ctx->public_key) EVP_PKEY_free(ctx->public_key); \
  if(ctx->private_key) EVP_PKEY_free(ctx->private_key); \
  free(ctx); \
 } \
} while(0)

#define _libssh2_x25519_free(ctx) _libssh2_ed25519_free(ctx)

#endif /* ED25519 */

#define _libssh2_cipher_type(name) const EVP_CIPHER *(*name)(void)
#ifdef HAVE_OPAQUE_STRUCTS
#define _libssh2_cipher_ctx EVP_CIPHER_CTX *
#else
#define _libssh2_cipher_ctx EVP_CIPHER_CTX
#endif

#define _libssh2_cipher_aes256 EVP_aes_256_cbc
#define _libssh2_cipher_aes192 EVP_aes_192_cbc
#define _libssh2_cipher_aes128 EVP_aes_128_cbc
#ifdef HAVE_EVP_AES_128_CTR
#define _libssh2_cipher_aes128ctr EVP_aes_128_ctr
#define _libssh2_cipher_aes192ctr EVP_aes_192_ctr
#define _libssh2_cipher_aes256ctr EVP_aes_256_ctr
#else
#define _libssh2_cipher_aes128ctr _libssh2_EVP_aes_128_ctr
#define _libssh2_cipher_aes192ctr _libssh2_EVP_aes_192_ctr
#define _libssh2_cipher_aes256ctr _libssh2_EVP_aes_256_ctr
#endif
#define _libssh2_cipher_blowfish EVP_bf_cbc
#define _libssh2_cipher_arcfour EVP_rc4
#define _libssh2_cipher_cast5 EVP_cast5_cbc
#define _libssh2_cipher_3des EVP_des_ede3_cbc

#define _libssh2_bn BIGNUM
#define _libssh2_bn_ctx BN_CTX

#define _libssh2_dh_ctx BIGNUM *

const EVP_CIPHER *_libssh2_EVP_aes_128_ctr(void);
const EVP_CIPHER *_libssh2_EVP_aes_192_ctr(void);
const EVP_CIPHER *_libssh2_EVP_aes_256_ctr(void);
