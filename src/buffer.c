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
    if(SSH2_BUF_IS_SECURE(buf))
        ssh2_buf_zero(buf);
    buf->size = 0;
}

void ssh2_buf_dispose(ssh2_buf *buf)
{
    ssh2_buf_clear(buf);
    if(buf && buf->asize) {
        LIBSSH2_FREE(buf->session, buf->ptr);
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

int ssh2_buf_detach(ssh2_buf *buf,
                   unsigned char **out_ptr, size_t *out_size,
                   size_t *out_asize)
{
    if(out_size)
        *out_size = buf->size;
    if(out_asize)
        *out_asize = buf->asize;

    if(out_ptr) {
        *out_ptr = buf->ptr;

        buf->ptr = NULL;
        buf->size = buf->asize = 0;

        ssh2_buf_dispose(buf);
        return 0;
    }
    return buf->size;
}

#define SSH2_BUFPAGE 256

int ssh2_buf_grow_(ssh2_buf *buf, size_t size, LIBSSH2_SESSION *session)
{
    size_t new_size = buf->asize + ((size / SSH2_BUFPAGE) + 1) * SSH2_BUFPAGE;

    if(buf->session == NULL && session != NULL)
        buf->session = session;
    else if(buf->session == NULL)
        return -1;

    unsigned char *tmp = LIBSSH2_REALLOC(buf->session, buf->ptr, new_size);
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

void ssh2_buf_zero(ssh2_buf *buf)
{
    _libssh2_explicit_zero(buf->ptr, buf->size);
}

void ssh2_databuf_dispose(ssh2_databuf *buf)
{
    if(buf == NULL)
        return;

//    ssh2_buf_dispose(&buf->buf);
    buf->data = NULL;
}

int ssh2_databuf_grow(ssh2_databuf *buf, size_t size)
{
    size_t offset = buf->data - ssh2_databuf_ptr(buf);
    if(ssh2_buf_grow_(&buf->buf, size, NULL) != 0)
        return -1;

    buf->data = ssh2_databuf_ptr(buf) + offset;

    return 0;
}

int ssh2_databuf_put(ssh2_databuf *buf, const unsigned char *data, size_t size)
{
    if(ssh2_buf_available(&buf->buf) < size &&
       ssh2_databuf_grow(buf, size) < 0)
        return -1;

    memcpy(buf->data, data, size);
    buf->data += size;
    buf->buf.size += size;
    return 0;
}

int ssh2_databuf_puts(ssh2_databuf *buf, const char *str)
{
    return ssh2_databuf_put(buf, (const unsigned char *)str, strlen(str));
}

int ssh2_databuf_put_u8(ssh2_databuf *buf, uint8_t value)
{
    if(ssh2_buf_available(&buf->buf) < sizeof(value) &&
       ssh2_databuf_grow(buf, sizeof(value)) < 0)
        return -1;

    *buf->data = value;
    buf->data += 1;
    buf->buf.size += sizeof(value);
    return 0;
}

int ssh2_databuf_put_u32(ssh2_databuf *buf, uint32_t value)
{
    if(ssh2_buf_available(&buf->buf) < sizeof(value) &&
       ssh2_databuf_grow(buf, sizeof(value)) < 0)
        return -1;

    _libssh2_htonu32(*buf->data, value);
    buf->data += sizeof(value);
    buf->buf.size += sizeof(value);
    return 0;
}

int ssh2_databuf_get_u32(ssh2_databuf *buf, uint32_t *out)
{
    if(!ssh2_databuf_check_length(buf, 4)) {
        return -1;
    }

    *out = _libssh2_ntohu32(buf->data);
    buf->data += 4;
    return 0;
}

int ssh2_databuf_get_u64(ssh2_databuf *buf, libssh2_uint64_t *out)
{
    if(!ssh2_databuf_check_length(buf, 8)) {
        return -1;
    }

    *out = _libssh2_ntohu64(buf->data);
    buf->data += 8;
    return 0;
}

int ssh2_databuf_match_string(ssh2_databuf *buf, const char *match)
{
    char *out;
    size_t len = 0;
    if(ssh2_databuf_get_string(buf, &out, &len) || len != strlen(match) ||
       strncmp((char *)out, match, strlen(match)) != 0) {
        return -1;
    }
    return 0;
}

int ssh2_databuf_get_ptr(ssh2_databuf *buf,
                         unsigned char **out_ptr, size_t *out_len)
{
    uint32_t data_len;
    if(ssh2_databuf_get_u32(buf, &data_len) != 0) {
        return -1;
    }
    if(!ssh2_databuf_check_length(buf, data_len)) {
        return -1;
    }

    if(out_ptr)
        *out_ptr = ssh2_databuf_ptr(buf);
    if(out_len)
        *out_len = (size_t)data_len;

    ssh2_databuf_advance(buf, data_len);

    return 0;
}

int ssh2_databuf_get_buf(ssh2_databuf *buf, ssh2_buf *out)
{
    size_t data_len;
    unsigned char *data;
    if(ssh2_databuf_get_ptr(buf, &data, &data_len) != 0) {
        return -1;
    }

    ssh2_buf_attach_(out, buf->data, data_len, NULL);

    return 0;
}

int ssh2_databuf_get_string(ssh2_databuf *buf, char **out_ptr, size_t *out_len)
{
    return ssh2_databuf_get_ptr(buf, (unsigned char **)out_ptr, out_len);
}

int ssh2_databuf_copy_ptr(LIBSSH2_SESSION *session, ssh2_databuf *buf,
                          unsigned char **outbuf, size_t *outlen)
{
    size_t str_len;
    unsigned char *str;

    if(ssh2_databuf_get_ptr(buf, &str, &str_len)) {
        return -1;
    }

    *outbuf = LIBSSH2_ALLOC(session, str_len);
    if(*outbuf) {
        memcpy(*outbuf, str, str_len);
    }
    else {
        return -1;
    }

    if(outlen)
        *outlen = str_len;

    return 0;
}

int ssh2_databuf_get_bn(ssh2_databuf *buf, unsigned char **outbuf,
                        size_t *outlen)
{
    uint32_t data_len;
    uint32_t bn_len;
    unsigned char *bnptr;

    if(ssh2_databuf_get_u32(buf, &data_len)) {
        return -1;
    }
    if(!ssh2_databuf_check_length(buf, data_len)) {
        return -1;
    }

    bn_len = data_len;
    bnptr = buf->data;

    /* trim leading zeros */
    while(bn_len > 0 && *bnptr == 0x00) {
        bn_len--;
        bnptr++;
    }

    *outbuf = bnptr;
    buf->data += data_len;

    if(outlen)
        *outlen = (size_t)bn_len;

    return 0;
}

/* Given the current location in buf, _libssh2_check_length ensures
 callers can read the next len number of bytes out of the buffer
 before reading the buffer content */

int ssh2_databuf_check_length(ssh2_databuf *buf, size_t len)
{
    unsigned char *endp = ssh2_buf_data(&buf->buf);
    size_t left = endp - ssh2_databuf_data(buf);
    return ((len <= left) && (left <= ssh2_databuf_size(buf)));
}
