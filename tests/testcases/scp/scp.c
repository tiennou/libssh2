#include "clar_libssh2.h"
#include "../userauth/userauth_helpers.h"

static LIBSSH2_SESSION *g_session = NULL;

void test_scp_scp__initialize_blocking(void)
{
    userauth_options opts = USERAUTH_OPTIONS_INIT;
    cl_fixture_sandbox("sftp");

    g_session = cl_ssh2_open_session_openssh(NULL, 1);

    opts.password = OPENSSH_PASSWORD;
    cl_userauth_authenticate(g_session, OPENSSH_USERNAME, &opts);
}

void test_scp_scp__initialize_nonblocking(void)
{
    cl_fixture_sandbox("sftp");

    g_session = cl_ssh2_open_session_openssh(NULL, 0);
}

void test_scp_scp__cleanup(void)
{
    cl_ssh2_close_connected_session();

    cl_fixture_cleanup("sftp");
}

void test_scp_scp__recv2(void)
{
    LIBSSH2_CHANNEL *channel;
    libssh2_struct_stat fileinfo;

    /* Request a file via SCP */
    cl_ssh2_check_ptr(channel,
                     libssh2_scp_recv2(g_session, SFTP_FILE_SONGOF7CITIES,
                                       &fileinfo));
}
