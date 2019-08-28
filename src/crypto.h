/* Copyright (C) 2009, 2010 Simon Josefsson
 * Copyright (C) 2006, 2007 The Written Word, Inc.  All rights reserved.
 * Copyright (C) 2010-2019 Daniel Stenberg
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
#ifndef LIBSSH2_CRYPTO_H
#define LIBSSH2_CRYPTO_H

#ifdef LIBSSH2_OPENSSL
#include "openssl.h"
#endif

#ifdef LIBSSH2_LIBGCRYPT
#include "libgcrypt.h"
#endif

#ifdef LIBSSH2_WINCNG
#include "wincng.h"
#endif

#ifdef LIBSSH2_OS400QC3
#include "os400qc3.h"
#endif

#ifdef LIBSSH2_MBEDTLS
#include "mbedtls.h"
#endif

#include "backend.h"

/*
 * Hash a message.
 *
 * This function hashes the given message with the given algorithm and
 * returns the result in out.
 *
 * Returns 0 on success, -1 on error.
 */
int libssh2_hash(libssh2_digest_algorithm algo,
                 const void *message, size_t len,
                 void *output);

void _libssh2_crypto_trace(LIBSSH2_SESSION *session,
                           const char *backend_id, const char *fmt, ...);
int _libssh2_crypto_error(LIBSSH2_SESSION *session,
                          libssh2_crypto_errcode error,
                          const char *backend_id, const char *fmt, ...);


#endif
