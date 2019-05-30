#include "clar_libssh2.h"
#include "userauth_helpers.h"

static const char *WRONG_PASSWORD = "i'm not the password";

void test_userauth_keyboard__initialize(void)
{
}

void test_userauth_keyboard__cleanup(void)
{
}

static void kbd_callback(const char *name, int name_len,
                         const char *instruction, int instruction_len,
                         int num_prompts,
                         const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                         LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                         void **abstract)
{
/*    int i; */
	const char *password = (const char *)*abstract;

/*
    fprintf(stdout, "Kb-int name: %.*s\n", name_len, name);
    fprintf(stdout, "Kb-int instruction: %.*s\n", instruction_len, instruction);
    for(i = 0; i < num_prompts; ++i) {
        fprintf(stdout, "Kb-int prompt %d: %.*s\n", i, prompts[i].length,
                prompts[i].text);
    }
*/

    if(num_prompts == 1) {
        responses[0].text = strdup(password);
        responses[0].length = strlen(password);
    }
}

void test_userauth_keyboard__interactive_auth_fails_with_wrong_response(void)
{
    int rc;
    LIBSSH2_SESSION *session;

	session = cl_ssh2_connect_openssh_session((void *)WRONG_PASSWORD);

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "keyboard-interactive");

    rc = libssh2_userauth_keyboard_interactive_ex(session, OPENSSH_USERNAME,
                                                  strlen(OPENSSH_USERNAME),
                                                  kbd_callback);

    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED, rc,
                 "Keyboard-interactive auth succeeded with wrong response");

	cl_ssh2_close_connected_session();
}

void test_userauth_keyboard__interactive_auth_succeeds_with_correct_response(void)
{
    int rc;
    LIBSSH2_SESSION *session;

	session = cl_ssh2_connect_openssh_session((void *)OPENSSH_PASSWORD);

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "keyboard-interactive");

    rc = libssh2_userauth_keyboard_interactive_ex(session, OPENSSH_USERNAME,
                                                  strlen(OPENSSH_USERNAME),
                                                  kbd_callback);

	cl_ssh2_check(rc);

	cl_ssh2_close_connected_session();
}
