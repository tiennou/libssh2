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

void test_core_databuf__put32(void)
{
    ssh2_databuf wr = SSH2_DATABUF_INIT(&g_buf);
    const uint8_t data[] = {0x00, 0x00, 0x04, 0x00};

    cl_assert_equal_i(0, ssh2_databuf_size(&wr));
    cl_must_pass(ssh2_databuf_put_u32(&wr, 1024));
    cl_check(memcmp(&data, ssh2_databuf_ptr(&wr), sizeof(data)) == 0);
    cl_assert_equal_i(4, ssh2_databuf_size(&wr));
}

#define NICE_STRING "this-nice-string"

void test_core_databuf__puts(void)
{
    ssh2_databuf wr = SSH2_DATABUF_INIT(&g_buf);
    const uint8_t data[] = {0x00,0x00,0x00,0x10,'t','h','i','s','-',
        'n','i','c','e','-','s','t','r','i','n','g'};

    ssh2_databuf_put_u32(&wr, strlen(NICE_STRING));
    cl_assert_equal_i(4, ssh2_databuf_size(&wr));

    ssh2_databuf_puts(&wr, NICE_STRING);
    cl_check(memcmp(&data, ssh2_buf_ptr(&g_buf), sizeof(data)) == 0);
    cl_assert_equal_i(4 + strlen(NICE_STRING), ssh2_buf_size(&g_buf));
}
