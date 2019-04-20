#include "clar_libssh2.h"
#include "misc.h"

static LIBSSH2_SESSION *g_session = NULL;

void test_core_buf__initialize(void)
{
	g_session = cl_ssh2_connect_openssh_session(NULL);
}

void test_core_buf__cleanup(void)
{
	cl_ssh2_close_connected_session();
}

void test_core_buf__grow(void)
{
	ssh_buf buf = SSH_BUF_INIT;
	ssh_buf buf_s = SSH_BUF_INIT_SESSION(g_session);

	cl_must_fail(ssh_buf_grow(&buf, 10));
	cl_must_pass(ssh_buf_grow_(&buf, 10, g_session));

	cl_must_pass(ssh_buf_grow(&buf_s, 10));

	ssh_buf_dispose(&buf);
	ssh_buf_dispose(&buf_s);
}

void test_core_buf__zero(void)
{
	ssh_buf buf = SSH_BUF_INIT_SESSION(g_session);

#ifndef LIBSSH2_SECURE_ZERO
	cl_skip();
#endif

	cl_must_pass(ssh_buf_random(&buf, 5));
	ssh_buf_zero(&buf);

	cl_assert_equal_i(0, buf.data[0]);
	cl_assert_equal_i(0, buf.data[1]);
	cl_assert_equal_i(0, buf.data[2]);
	cl_assert_equal_i(0, buf.data[3]);
	cl_assert_equal_i(0, buf.data[4]);

	ssh_buf_dispose(&buf);
}
