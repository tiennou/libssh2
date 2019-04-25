/*
 * Copyright (C) 2008, 2009, 2010 Simon Josefsson
 * Copyright (C) 2006, 2007, The Written Word, Inc.
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

#include <gcrypt.h>

#define LIBSSH2_MD5 1

#define LIBSSH2_HMAC_RIPEMD 1
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_BLOWFISH 1
#define LIBSSH2_RC4 1
#define LIBSSH2_CAST 1
#define LIBSSH2_3DES 1

#define LIBSSH2_RSA 1
#define LIBSSH2_DSA 1
#define LIBSSH2_ECDSA 0
#define LIBSSH2_ED25519 0

#define libssh2_sha1_ctx gcry_md_hd_t
#define libssh2_sha256_ctx gcry_md_hd_t
#define libssh2_sha384_ctx gcry_md_hd_t
#define libssh2_sha512_ctx gcry_md_hd_t
#define libssh2_md5_ctx gcry_md_hd_t
#define libssh2_hmac_ctx gcry_md_hd_t

#define libssh2_rsa_ctx struct gcry_sexp
#define libssh2_dsa_ctx struct gcry_sexp

#if LIBSSH2_ECDSA
#else
#define _libssh2_ec_key void
#endif

#define _libssh2_cipher_type(name) int name
#define _libssh2_cipher_ctx gcry_cipher_hd_t

#define _libssh2_gcry_ciphermode(c,m) ((c << 8) | m)
#define _libssh2_gcry_cipher(c) (c >> 8)
#define _libssh2_gcry_mode(m) (m & 0xFF)

#define _libssh2_cipher_aes256ctr \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR)
#define _libssh2_cipher_aes192ctr \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR)
#define _libssh2_cipher_aes128ctr \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR)
#define _libssh2_cipher_aes256 \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC)
#define _libssh2_cipher_aes192 \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC)
#define _libssh2_cipher_aes128 \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC)
#define _libssh2_cipher_blowfish \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC)
#define _libssh2_cipher_arcfour \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM)
#define _libssh2_cipher_cast5 \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CBC)
#define _libssh2_cipher_3des \
  _libssh2_gcry_ciphermode(GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC)

#define _libssh2_bn struct gcry_mpi
#define _libssh2_bn_ctx int

#define _libssh2_dh_ctx struct gcry_mpi *
