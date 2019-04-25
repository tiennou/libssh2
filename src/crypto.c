/* Copyright (C) 2016, Etienne Samson
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

#include "libssh2_priv.h"
#include <stdarg.h>

int libssh2_hash(libssh2_digest_algorithm algo,
                 const void *message, unsigned long len,
                 void *out)
{
    libssh2_digest_ctx ctx;
    int err = libssh2_digest_init(&ctx, algo);
    if(err != 0) {
        return err;
    }

    libssh2_digest_update(ctx, message, len);
    libssh2_digest_final(ctx, out);

    return 0;
}

int libssh2_digest_size(libssh2_digest_algorithm algo)
{
    switch(algo) {
#ifdef LIBSSH2_MD5
        case libssh2_digest_MD5: return MD5_DIGEST_LENGTH;
#endif
        case libssh2_digest_SHA1: return SHA_DIGEST_LENGTH;
        case libssh2_digest_SHA256: return SHA256_DIGEST_LENGTH;
        case libssh2_digest_SHA384: return SHA384_DIGEST_LENGTH;
#ifdef LIBSSH2_HMAC_SHA512
        case libssh2_digest_SHA512: return SHA512_DIGEST_LENGTH;
#endif
#ifdef LIBSSH2_HMAC_RIPEMD
        case libssh2_digest_RIPEMD160: return RIPEMD160_DIGEST_LENGTH;
#endif
        default: return -1;
    }
}

/* _libssh2_ecdsa_curve_type_from_name
 *
 * returns 0 for success, key curve type that maps to libssh2_curve_type
 *
 */

int
_libssh2_ecdsa_curve_type_from_name(const char *name,
                                    libssh2_curve_type *out_type)
{
#if defined(LIBSSH2_ECDSA) && LIBSSH2_ECDSA
    int ret = 0;
    libssh2_curve_type type;
    if(name == NULL || strlen(name) != 19)
        return -1;

    if(strcmp(name, "ecdsa-sha2-nistp256") == 0)
        type = LIBSSH2_EC_CURVE_NISTP256;
    else if(strcmp(name, "ecdsa-sha2-nistp384") == 0)
        type = LIBSSH2_EC_CURVE_NISTP384;
    else if(strcmp(name, "ecdsa-sha2-nistp521") == 0)
        type = LIBSSH2_EC_CURVE_NISTP521;
    else {
        ret = -1;
    }

    if(ret == 0 && out_type) {
        *out_type = type;
    }

    return ret;
#else
    return -1;
#endif
}

int _libssh2_crypto_error(LIBSSH2_SESSION *session,
                          libssh2_crypto_errcode error,
                          const char *backend_id, const char *fmt, ...)
{
    va_list args;
    char msg[2048];
    char errmsg[256];

    _libssh2_crypto_errormsg(error, errmsg, sizeof(errmsg));

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    snprintf(msg, sizeof(msg), "%s: %s => %s", backend_id, msg, errmsg);

    return _libssh2_error(session, LIBSSH2_ERROR_CRYPTO, msg);
}


void _libssh2_crypto_trace(LIBSSH2_SESSION *session,
                           const char *backend_id, const char *fmt, ...)
{
    va_list args;
    char msg[2048];

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    snprintf(msg, sizeof(msg), "%s: %s", backend_id, msg);

    if(session)
        _libssh2_debug(session, LIBSSH2_TRACE_CRYPTO, "%s", msg);
    else
#ifdef LIBSSH2DEBUG
        fprintf(stderr, "%s", msg);
#endif
}

void _libssh2_crypto_trace(const char *fmt, ...)
{
    va_list args;
    char msg[2048];

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    fprintf(stderr, "%s", msg);
}
