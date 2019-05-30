#include "clar_libssh2.h"
#include "userauth_helpers.h"

static LIBSSH2_SESSION *session;

void test_userauth_publickey__initialize(void)
{
    session = cl_ssh2_connect_openssh_session(NULL);
	cl_fixture_sandbox("publickeys");
}

void test_userauth_publickey__cleanup(void)
{
    cl_ssh2_close_connected_session();
	cl_fixture_cleanup("publickeys");
}

void test_userauth_publickey__auth_fails_with_wrong_key(void)
{
    int rc;
    struct stat _stat;
    cl_must_pass(stat(WRONG_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(WRONG_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), WRONG_KEYFILE_PUBLIC, WRONG_KEYFILE_PRIVATE,
        NULL);
    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED, rc,
                 "Public-key auth succeeded with wrong key");
}

void test_userauth_publickey__dsa_auth_ok(void)
{
    int rc;
    struct stat _stat;

#if defined(LIBSSH2_DSA) && !LIBSSH2_DSA
	cl_skip();
#endif

    cl_must_pass(stat(DSA_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(DSA_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), DSA_KEYFILE_PUBLIC, DSA_KEYFILE_PRIVATE,
        NULL);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__ed25519_auth_ok(void)
{
    int rc;
    struct stat _stat;

#if defined(LIBSSH2_ED25519) && !LIBSSH2_ED25519
	cl_skip();
#endif

    cl_must_pass(stat(ED25519_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(ED25519_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), ED25519_KEYFILE_PUBLIC, ED25519_KEYFILE_PRIVATE,
        NULL);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__ed25519_mem_auth_ok(void)
{
    int rc;
    char *buffer = NULL;
    size_t len = 0;

#if defined(LIBSSH2_ED25519) && !LIBSSH2_ED25519
	cl_skip();
#endif

    cl_userauth_check_mech(session, USERNAME, "publickey");

    if(cl_ssh2_read_file(ED25519_KEYFILE_PRIVATE, &buffer, &len)) {
        cl_fail("Reading key file failed");
    }

    rc = libssh2_userauth_publickey_frommemory(session, USERNAME, strlen(USERNAME),
                                               NULL, 0, buffer, len, NULL);

    free(buffer);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__ed25519_encrypted_auth_ok(void)
{
    int rc;
    struct stat _stat;

#if defined(LIBSSH2_ED25519) && !LIBSSH2_ED25519
	cl_skip();
#endif

    cl_must_pass(stat(ED25519_KEYFILE_ENC_PUBLIC, &_stat));
    cl_must_pass(stat(ED25519_KEYFILE_ENC_PRIVATE, &_stat));

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), ED25519_KEYFILE_ENC_PUBLIC,
        ED25519_KEYFILE_ENC_PRIVATE, ED25519_KEYFILE_PASSWORD);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__rsa_encrypted_auth_ok(void)
{
    int rc;
    struct stat _stat;

#if defined(LIBSSH2_RSA) && !LIBSSH2_RSA
	cl_skip();
#endif

    cl_must_pass(stat(RSA_KEYFILE_ENC_PUBLIC, &_stat));
    cl_must_pass(stat(RSA_KEYFILE_ENC_PRIVATE, &_stat));

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), RSA_KEYFILE_ENC_PUBLIC,
        RSA_KEYFILE_ENC_PRIVATE, RSA_KEYFILE_PASSWORD);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__rsa_auth_ok(void)
{
    int rc;
	struct stat _stat;

#if defined(LIBSSH2_RSA) && !LIBSSH2_RSA
	cl_skip();
#endif

    cl_must_pass(stat(RSA_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(RSA_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), RSA_KEYFILE_PUBLIC, RSA_KEYFILE_PRIVATE,
        NULL);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__rsa_openssh_auth_ok(void)
{
    int rc;
    struct stat _stat;

#if defined(LIBSSH2_RSA) && !LIBSSH2_RSA || !defined(LIBSSH2_OPENSSL)
	cl_skip();
#endif

    cl_must_pass(stat(RSA_OPENSSH_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(RSA_OPENSSH_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), RSA_OPENSSH_KEYFILE_PUBLIC,
        RSA_OPENSSH_KEYFILE_PRIVATE, NULL);

    cl_ssh2_check(rc);
}
