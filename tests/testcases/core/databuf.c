#include "clar_libssh2.h"
#include "misc.h"

static LIBSSH2_SESSION *g_session = NULL;
static ssh2_buf g_buf = SSH2_BUF_INIT;

void test_core_databuf__initialize(void)
{
    g_session = cl_ssh2_open_session(NULL, 1);
    ssh2_buf_init_session(&g_buf, g_session);
}

void test_core_databuf__cleanup(void)
{
    ssh2_buf_dispose(&g_buf);
    cl_ssh2_close_connected_session();
}

void test_core_databuf__init(void)
{
    ssh2_databuf buf = SSH2_DATABUF_INIT(&g_buf);

    cl_assert_equal_i(0, ssh2_databuf_size(&buf));
    cl_assert_equal_p(ssh2_buf_ptr(&g_buf), ssh2_databuf_ptr(&buf));
    cl_assert_equal_p(ssh2_buf_ptr(&g_buf), ssh2_databuf_data(&buf));

    cl_must_fail(ssh2_databuf_advance(&buf, 1));

    ssh2_databuf_dispose(&buf);
}

void test_core_databuf__advance(void)
{
    ssh2_buf _buf = SSH2_BUF_CSTR("test-string");
    ssh2_databuf buf = SSH2_DATABUF_INIT(&_buf);

    cl_assert_equal_i(11, ssh2_databuf_size(&buf));
    cl_assert_equal_p(ssh2_buf_ptr(&_buf), ssh2_databuf_ptr(&buf));
    cl_assert_equal_p(ssh2_buf_ptr(&_buf), ssh2_databuf_data(&buf));

    cl_must_pass(ssh2_databuf_advance(&buf, 5));
    cl_must_pass(ssh2_databuf_advance(&buf, 5));
    cl_must_fail(ssh2_databuf_advance(&buf, 5));

    ssh2_databuf_dispose(&buf);
}
