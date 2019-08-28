/* Copyright (c) 2016, Art <https://github.com/wildart>
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

#include <stdlib.h>
#include <string.h>

#include <mbedtls/platform.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

/* Define which features are supported. */
#define LIBSSH2_MD5             1

#define LIBSSH2_HMAC_RIPEMD     1
#define LIBSSH2_HMAC_SHA256     1
#define LIBSSH2_HMAC_SHA512     1

#define LIBSSH2_AES             1
#define LIBSSH2_AES_CTR         1
#define LIBSSH2_BLOWFISH        1
#define LIBSSH2_RC4             1
#define LIBSSH2_CAST            0
#define LIBSSH2_3DES            1

#define LIBSSH2_RSA             1
#define LIBSSH2_DSA             0
#define LIBSSH2_ECDSA           0
#define LIBSSH2_ED25519         0

#define libssh2_crypto_errcode int

/*******************************************************************/
/*
 * mbedTLS backend: Digest
 */

#define libssh2_hmac_ctx     mbedtls_md_context_t
#define libssh2_sha1_ctx     mbedtls_md_context_t
#define libssh2_sha256_ctx   mbedtls_md_context_t
#define libssh2_sha384_ctx   mbedtls_md_context_t
#define libssh2_sha512_ctx   mbedtls_md_context_t
#define libssh2_md5_ctx      mbedtls_md_context_t

/*******************************************************************/
/*
 * mbedTLS backend: RSA structure
 */

#define libssh2_rsa_ctx  mbedtls_rsa_context

/*******************************************************************/
/*
 * mbedTLS backend: Ciphers
 */
#define _libssh2_cipher_ctx         mbedtls_cipher_context_t

#define _libssh2_cipher_type(algo)  mbedtls_cipher_type_t algo

#define _libssh2_cipher_aes256ctr MBEDTLS_CIPHER_AES_256_CTR
#define _libssh2_cipher_aes192ctr MBEDTLS_CIPHER_AES_192_CTR
#define _libssh2_cipher_aes128ctr MBEDTLS_CIPHER_AES_128_CTR
#define _libssh2_cipher_aes256    MBEDTLS_CIPHER_AES_256_CBC
#define _libssh2_cipher_aes192    MBEDTLS_CIPHER_AES_192_CBC
#define _libssh2_cipher_aes128    MBEDTLS_CIPHER_AES_128_CBC
#define _libssh2_cipher_blowfish  MBEDTLS_CIPHER_BLOWFISH_CBC
#define _libssh2_cipher_arcfour   MBEDTLS_CIPHER_ARC4_128
#define _libssh2_cipher_cast5     MBEDTLS_CIPHER_NULL
#define _libssh2_cipher_3des      MBEDTLS_CIPHER_DES_EDE3_CBC

#define _libssh2_bn_ctx int /* not used */
#define _libssh2_bn mbedtls_mpi

#define _libssh2_dh_ctx mbedtls_mpi *
