/* Copyright (c) 2019 by Etienne Samson
 *
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

#include "libssh2_priv.h"
#include "buffer.h"

void ssh2_buf_clear(ssh2_buf *buf)
{
    buf->size = 0;
}

void ssh2_buf_dispose(ssh2_buf *buf)
{
    ssh2_buf_clear(buf);
    if(buf && buf->asize) {
        if(buf->session)
            LIBSSH2_FREE(buf->session, buf->ptr);
        else
            /* this is gonna leak */
        buf->ptr = NULL;
        buf->size = buf->asize = 0;
    }
}

void ssh2_buf_swap(ssh2_buf *buf, ssh2_buf *swp)
{
    ssh2_buf tmp = SSH2_BUF_INIT;

    memcpy(&tmp, buf, sizeof(tmp));
    memcpy(buf, swp, sizeof(*swp));
    memcpy(swp, &tmp, sizeof(*swp));
}

int ssh2_buf_cpy(ssh2_buf *dst, const ssh2_buf *src)
{
    if(ssh2_buf_grow(dst, ssh2_buf_size(src)) != 0)
        return -1;

    ssh2_buf_clear(dst);

    memmove(dst->ptr, src->ptr, src->size);
    dst->size = src->size;

    return 0;
}

void ssh2_buf_attach_(ssh2_buf *buf, unsigned char *data, size_t size,
                     LIBSSH2_SESSION *session)
{
    ssh2_buf_clear(buf);
    ssh2_buf_init(buf, data, size);
    buf->session = session;
}

#define SSH2_BUFPAGE 256

int ssh2_buf_grow_(ssh2_buf *buf, size_t size, LIBSSH2_SESSION *session)
{
    size_t new_size = buf->asize + ((size / SSH2_BUFPAGE) + 1) * SSH2_BUFPAGE;
    unsigned char *tmp;

    if(buf->session == NULL && session != NULL)
        buf->session = session;
    else if(buf->session == NULL)
        return -1;

    tmp = LIBSSH2_REALLOC(buf->session, buf->ptr, new_size);
    if(tmp == NULL)
        return -1;

    buf->ptr = tmp;
    buf->asize = new_size;

    return 0;
}

int ssh2_buf_grow(ssh2_buf *buf, size_t size)
{
    return ssh2_buf_grow_(buf, size, NULL);
}

int ssh2_buf_random(ssh2_buf *buf, size_t len)
{
    if(ssh2_buf_available(buf) < len && ssh2_buf_grow(buf, len) < 0)
        return -1;

    _libssh2_random(buf->ptr + buf->size, len);
    buf->size += len;
    return 0;
}
