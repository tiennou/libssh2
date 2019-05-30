#include "clar_libssh2.h"
#include "userauth_helpers.h"

static const char *WRONG_USERNAME = "i dont exist";
static const char *WRONG_PASSWORD = "i'm not the password";

static LIBSSH2_SESSION *session;

void test_userauth_password__initialize(void)
{
	session = cl_ssh2_connect_openssh_session(NULL);
}

void test_userauth_password__cleanup(void)
{
    cl_ssh2_close_connected_session();
}

void test_userauth_password__auth_fails_with_wrong_username(void)
{
    int rc;

    cl_userauth_check_mech(session, WRONG_USERNAME, "password");

    rc = libssh2_userauth_password_ex(session, WRONG_USERNAME,
                                      strlen(WRONG_USERNAME), PASSWORD,
                                      strlen(PASSWORD), NULL);
    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED, rc,
                 "Password auth succeeded with wrong username");
}

void test_userauth_password__auth_fails_with_wrong_password(void)
{
    int rc;

    cl_userauth_check_mech(session, USERNAME, "password");

    rc = libssh2_userauth_password_ex(session, USERNAME, strlen(USERNAME),
                                      WRONG_PASSWORD, strlen(WRONG_PASSWORD),
                                      NULL);
    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED, rc,
                 "Password auth succeeded with wrong password");
}

void test_userauth_password__auth_succeeds_with_correct_credentials(void)
{
    int rc;

    cl_userauth_check_mech(session, USERNAME, "password");

    rc = libssh2_userauth_password_ex(session, USERNAME, strlen(USERNAME),
                                      PASSWORD, strlen(PASSWORD), NULL);
    cl_ssh2_check(rc);
    cl_assert_(libssh2_userauth_authenticated(session) != 0,
               "Password auth appeared to succeed but "
               "libssh2_userauth_authenticated returned 0");
}
