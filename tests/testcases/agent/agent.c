#include "clar_libssh2.h"
#include "../userauth/userauth_helpers.h"

static LIBSSH2_SESSION *g_session;

void test_agent_agent__initialize(void)
{
    g_session = cl_ssh2_open_session_openssh(NULL, 1);
}

void test_agent_agent__cleanup(void)
{
    cl_ssh2_close_connected_session();
}

void test_agent_agent__basic(void)
{
    LIBSSH2_AGENT *agent;
    struct libssh2_agent_publickey *identity, *prev_identity = NULL;

    /* Connect to the ssh-agent */
    cl_ssh2_check_ptr(agent, libssh2_agent_init(g_session));

    cl_ssh2_check(libssh2_agent_connect(agent));
    cl_ssh2_check(libssh2_agent_list_identities(agent));

    while(1) {
        int rc = libssh2_agent_get_identity(agent, &identity, prev_identity);
        if(rc == 1)
            break;

        cl_ssh2_check(rc);

        cl_ssh2_check(libssh2_agent_userauth(agent,
                                             OPENSSH_USERNAME, identity));

        prev_identity = identity;
    }

    /* We're authenticated now. */
}
