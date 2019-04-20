#ifndef __LIBSSH2_MISC_H
#define __LIBSSH2_MISC_H
/* Copyright (c) 2009-2019 by Daniel Stenberg
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

struct list_head {
    struct list_node *last;
    struct list_node *first;
};

struct list_node {
    struct list_node *next;
    struct list_node *prev;
    struct list_head *head;
};

typedef struct ssh_buf {
    unsigned char *data;
	size_t asize;
	size_t size;
    unsigned char *dataptr;
	LIBSSH2_SESSION *session;
	int secure : 1;
} ssh_buf;

#define SSH_BUF_INIT { NULL, NULL, 0, NULL, NULL }
#define SSH_BUF_INIT_SESSION(s) { NULL, NULL, 0, NULL, (s) }
#define SSH_BUF_SECINIT { NULL, NULL, 0, NULL, NULL, 1 }
#define SSH_BUF_SECINIT_SESSION(s) { NULL, NULL, 0, NULL, (s), 1 }
#define SSH_BUF_CONST(data, size) { (data), NULL, (size), (data), NULL }
#define SSH_BUF_CSTR(str) { str, NULL, strlen(str), str, NULL }

int _libssh2_error_flags(LIBSSH2_SESSION* session, int errcode,
                         const char *errmsg, int errflags);
int _libssh2_error(LIBSSH2_SESSION* session, int errcode, const char *errmsg);

void _libssh2_list_init(struct list_head *head);

/* add a node last in the list */
void _libssh2_list_add(struct list_head *head,
                       struct list_node *entry);

/* return the "first" node in the list this head points to */
void *_libssh2_list_first(struct list_head *head);

/* return the next node in the list */
void *_libssh2_list_next(struct list_node *node);

/* return the prev node in the list */
void *_libssh2_list_prev(struct list_node *node);

/* remove this node from the list */
void _libssh2_list_remove(struct list_node *entry);

size_t _libssh2_base64_encode(LIBSSH2_SESSION *session,
                              const char *inp, size_t insize, char **outptr);

static inline void ssh_buf_init_unowned(ssh_buf *buf, unsigned char *data, size_t size)
{
	buf->data = buf->dataptr = data;
	buf->size = size;
}

static inline void ssh_buf_init(ssh_buf *buf, unsigned char *data, size_t size)
{
	ssh_buf_init_unowned(buf, data, size);
	buf->asize = size;
}

static inline unsigned char *ssh_buf_ptr(const ssh_buf *buf)
{
	return buf->data;
}

static inline unsigned char *ssh_buf_data(const ssh_buf *buf)
{
	return buf->dataptr;
}

static inline size_t ssh_buf_size(const ssh_buf *buf)
{
	return buf->size;
}

static inline size_t ssh_buf_available(const ssh_buf *buf)
{
	if (buf->asize == 0)
		return 0;

	return buf->asize - buf->size;
}

unsigned int _libssh2_ntohu32(const unsigned char *buf);
libssh2_uint64_t _libssh2_ntohu64(const unsigned char *buf);
void _libssh2_htonu32(unsigned char *buf, uint32_t val);
void _libssh2_store_u32(unsigned char **buf, uint32_t value);
void _libssh2_store_str(unsigned char **buf, const char *str, size_t len);
void *_libssh2_calloc(LIBSSH2_SESSION *session, size_t size);
void _libssh2_explicit_zero(void *buf, size_t size);

ssh_buf *ssh_buf_new(LIBSSH2_SESSION *session);
void ssh_buf_attach_(ssh_buf *buf,
					 unsigned char *data, size_t size,
					 LIBSSH2_SESSION *session);
int ssh_buf_grow_(ssh_buf *buf, size_t size, LIBSSH2_SESSION *session);
int ssh_buf_grow(ssh_buf *buf, size_t size);
void ssh_buf_clear(ssh_buf *buf);
void ssh_buf_dispose(ssh_buf *buf);

int ssh_buf_random(ssh_buf *buf, size_t len);
void ssh_buf_zero(ssh_buf *buf);

int ssh_buf_put(ssh_buf *buf, const char *data, size_t size);
int ssh_buf_puts(ssh_buf *buf, const char *str);

void _libssh2_string_buf_free(LIBSSH2_SESSION *session, ssh_buf *buf);
int _libssh2_get_u32(ssh_buf *buf, uint32_t *out);
int _libssh2_get_u64(ssh_buf *buf, libssh2_uint64_t *out);
int _libssh2_match_string(ssh_buf *buf, const char *match);
int _libssh2_get_c_string(ssh_buf *buf, unsigned char **outbuf);
int _libssh2_get_bignum_bytes(ssh_buf *buf, unsigned char **outbuf);
int _libssh2_check_length(ssh_buf *buf, size_t requested_len);

#if defined(LIBSSH2_WIN32) && !defined(__MINGW32__) && !defined(__CYGWIN__)
/* provide a private one */
#undef HAVE_GETTIMEOFDAY
int __cdecl _libssh2_gettimeofday(struct timeval *tp, void *tzp);
#define HAVE_LIBSSH2_GETTIMEOFDAY
#define LIBSSH2_GETTIMEOFDAY_WIN32 /* enable the win32 implementation */
#else
#ifdef HAVE_GETTIMEOFDAY
#define _libssh2_gettimeofday(x,y) gettimeofday(x,y)
#define HAVE_LIBSSH2_GETTIMEOFDAY
#endif
#endif

void _libssh2_xor_data(unsigned char *output,
                       const unsigned char *input1,
                       const unsigned char *input2,
                       size_t length);

void _libssh2_aes_ctr_increment(unsigned char *ctr, size_t length);

#endif /* _LIBSSH2_MISC_H */
