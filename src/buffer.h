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

#ifndef __LIBSSH2_BUFFER_H
#define __LIBSSH2_BUFFER_H

typedef struct ssh2_buf {
    unsigned char *ptr;
    size_t size;
    size_t asize;
    LIBSSH2_SESSION *session;
} ssh2_buf;

#define SSH2_BUF_INIT { NULL, 0, 0, NULL }
#define SSH2_BUF_INIT_SESSION(s) { NULL, 0, 0, (s) }
#define SSH2_BUF_CONST(data, size) { (data), (size), 0, NULL }
#define SSH2_BUF_CSTR(str) { (str), strlen(str), 0, NULL }

static inline void ssh2_buf_init_unowned(ssh2_buf *buf,
                                        unsigned char *data, size_t size)
{
    buf->ptr = data;
    buf->size = size;
}

static inline void ssh2_buf_init(ssh2_buf *buf,
                                 unsigned char *data, size_t size)
{
    ssh2_buf_init_unowned(buf, data, size);
    buf->asize = size;
}

static inline void ssh2_buf_init_session(ssh2_buf *buf,
                                         LIBSSH2_SESSION *session)
{
    ssh2_buf_init(buf, NULL, 0);
    buf->session = session;
}

static inline unsigned char *ssh2_buf_ptr(const ssh2_buf *buf)
{
    return buf->ptr;
}

static inline unsigned char *ssh2_buf_data(const ssh2_buf *buf)
{
    return buf->ptr + buf->size;
}

static inline size_t ssh2_buf_size(const ssh2_buf *buf)
{
    return buf->size;
}

static inline size_t ssh2_buf_available(const ssh2_buf *buf)
{
    if(buf->asize == 0)
        return 0;

    return buf->asize - buf->size;
}

void ssh2_buf_attach_(ssh2_buf *buf,
                     unsigned char *data, size_t size,
                     LIBSSH2_SESSION *session);
int ssh2_buf_grow_(ssh2_buf *buf, size_t size, LIBSSH2_SESSION *session);
int ssh2_buf_grow(ssh2_buf *buf, size_t size);
int ssh2_buf_cpy(ssh2_buf *dst, const ssh2_buf *src);
void ssh2_buf_clear(ssh2_buf *buf);
void ssh2_buf_dispose(ssh2_buf *buf);
void ssh2_buf_swap(ssh2_buf *buf, ssh2_buf *swp);

int ssh2_buf_random(ssh2_buf *buf, size_t len);

#endif
