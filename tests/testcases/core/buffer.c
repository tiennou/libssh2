#include "clar_libssh2.h"
#include "misc.h"

static LIBSSH2_SESSION *g_session = NULL;

void test_core_buffer__initialize(void)
{
    g_session = cl_ssh2_open_session(NULL, 1);
}

void test_core_buffer__cleanup(void)
{
    cl_ssh2_close_connected_session();
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
