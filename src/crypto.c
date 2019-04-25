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

#define HASH_FUNCTION(hash) \
int _libssh2_##hash (const void *message, size_t len, void *out) \
{ \
    libssh2_##hash##_ctx ctx; \
    int err = libssh2_##hash##_init(&ctx); \
    if(err != 0) { \
        return -1; \
    } \
 \
    libssh2_##hash##_update(ctx, message, len); \
    libssh2_##hash##_final(ctx, out); \
 \
    return 0; \
}

HASH_FUNCTION(sha1);
HASH_FUNCTION(sha256);
HASH_FUNCTION(sha384);
HASH_FUNCTION(sha512);
HASH_FUNCTION(md5);

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
