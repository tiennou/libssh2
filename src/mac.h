#ifndef __LIBSSH2_MAC_H
#define __LIBSSH2_MAC_H

/* Copyright (C) 2009-2010 by Daniel Stenberg
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
 *
 */

#include "libssh2_priv.h"

struct _LIBSSH2_MAC_METHOD
{
    const char *name;

    /* The length of a given MAC packet */
    int mac_len;

    /* integrity key length */
    int key_len;

	_libssh2_cipher_type(algo);

    /* Message Authentication Code Hashing algo */
    int (*init) (_LIBSSH2_MAC_HASHER **out,
				 const struct _LIBSSH2_MAC_METHOD *method,
				 LIBSSH2_SESSION *session, _libssh2_cipher_type(algo),
				 const ssh_buf *key);
	int (*hash) (ssh_buf *out, _LIBSSH2_MAC_HASHER *meth, uint32_t seqno,
				 const ssh_buf *packet, const ssh_buf *addtl);
    int (*dtor) (_LIBSSH2_MAC_HASHER *meth);
};

typedef struct _LIBSSH2_MAC_METHOD LIBSSH2_MAC_METHOD;

const LIBSSH2_MAC_METHOD **_libssh2_mac_methods(void);

int _libssh2_mac_init(_LIBSSH2_MAC_HASHER **out,
					  const struct _LIBSSH2_MAC_METHOD *method,
					  LIBSSH2_SESSION *session, _libssh2_cipher_type(algo),
					  const ssh_buf *key);
int _libssh2_mac_hash(ssh_buf *buf, _LIBSSH2_MAC_HASHER *hash,
					  uint32_t seqno,
					  const ssh_buf *packet, const ssh_buf *addtl);
int _libssh2_mac_free(_LIBSSH2_MAC_HASHER *meth);

#endif /* __LIBSSH2_MAC_H */
