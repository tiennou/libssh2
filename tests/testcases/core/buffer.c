#include "clar_libssh2.h"
#include "misc.h"

static LIBSSH2_SESSION *g_session = NULL;
static unsigned char *g_buf[2048];

void test_core_buffer__initialize(void)
{
    g_session = cl_ssh2_open_session(NULL, 1);
}

void test_core_buffer__cleanup(void)
{
    cl_ssh2_close_connected_session();
}

void test_core_buffer__init_unowned(void)
{
    ssh2_buf buf = SSH2_BUF_INIT;
    size_t ptr_size = 32;
    void *ptr = malloc(ptr_size);
    cl_assert(ptr != NULL);

    ssh2_buf_init_unowned(&buf, ptr, ptr_size);
    cl_assert_equal_p(ptr, buf.ptr);
    cl_assert_equal_i(ptr_size, buf.size);
    cl_assert_equal_i(0, buf.asize);

    ssh2_buf_random(&buf, 10);

    ssh2_buf_dispose(&buf);
    free(ptr);
}

void test_core_buffer__attach(void)
{
    ssh2_buf buf = SSH2_BUF_INIT;
    size_t ptr_size = 32;
    void *ptr = malloc(ptr_size);
    cl_assert(ptr != NULL);

    ssh2_buf_attach_(&buf, ptr, ptr_size, NULL);
    ssh2_buf_random(&buf, 10);

    ssh2_buf_dispose(&buf);
}

void test_core_buffer__attach_session(void)
{
    ssh2_buf buf = SSH2_BUF_INIT_SESSION(g_session);
    size_t ptr_size = 32;
    void *ptr = malloc(ptr_size);
    cl_assert(ptr != NULL);

    ssh2_buf_attach_(&buf, ptr, ptr_size, g_session);
    ssh2_buf_random(&buf, 10);

    ssh2_buf_dispose(&buf);
}

void test_core_buffer__detach(void)
{
    ssh2_buf buf = SSH2_BUF_INIT_SESSION(g_session);
    unsigned char *ptr;
    size_t ptr_size, ptr_asize;
    ssh2_buf_random(&buf, 10);

    cl_must_pass(ssh2_buf_detach(&buf, &ptr, &ptr_size, &ptr_asize));

    ssh2_buf_dispose(&buf);
    free(ptr);
}

void test_core_buffer__cpy(void)
{
    ssh2_buf org = SSH2_BUF_CONST((unsigned char *)g_buf, sizeof(g_buf));
    ssh2_buf cpy = SSH2_BUF_INIT_SESSION(g_session);

    ssh2_buf_random(&org, 64);

    cl_must_pass(ssh2_buf_cpy(&cpy, &org));
    cl_assert_equal_i(ssh2_buf_size(&org), ssh2_buf_size(&cpy));
    cl_assert_equal_strn(ssh2_buf_ptr(&org), ssh2_buf_ptr(&cpy),
                         ssh2_buf_size(&org));

    ssh2_buf_dispose(&org);
    ssh2_buf_dispose(&cpy);
}

void test_core_buffer__grow(void)
{
    ssh2_buf buf = SSH2_BUF_INIT;
    ssh2_buf buf_s = SSH2_BUF_INIT_SESSION(g_session);

    cl_must_fail(ssh2_buf_grow(&buf, 10));
    cl_must_pass(ssh2_buf_grow_(&buf, 10, g_session));

    cl_must_pass(ssh2_buf_grow(&buf_s, 10));

    ssh2_buf_dispose(&buf);
    ssh2_buf_dispose(&buf_s);
}

void test_core_buffer__random(void)
{
    ssh2_buf buf = SSH2_BUF_INIT_SESSION(g_session);

    cl_must_pass(ssh2_buf_random(&buf, 256));
    cl_assert_equal_i(256, ssh2_buf_size(&buf));

    cl_must_pass(ssh2_buf_random(&buf, 256));
    cl_assert_equal_i(512, ssh2_buf_size(&buf));

    ssh2_buf_dispose(&buf);
}

void test_core_buffer__zero(void)
{
    ssh2_buf buf = SSH2_BUF_INIT_SESSION(g_session);

#ifndef LIBSSH2_SECURE_ZERO
    cl_skip();
#endif

    cl_must_pass(ssh2_buf_random(&buf, 5));
    cl_assert_equal_i(5, ssh2_buf_size(&buf));
    ssh2_buf_zero(&buf);

    cl_assert_equal_i(0, buf.ptr[0]);
    cl_assert_equal_i(0, buf.ptr[1]);
    cl_assert_equal_i(0, buf.ptr[2]);
    cl_assert_equal_i(0, buf.ptr[3]);
    cl_assert_equal_i(0, buf.ptr[4]);

    ssh2_buf_dispose(&buf);
}
