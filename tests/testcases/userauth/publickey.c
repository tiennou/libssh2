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

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), DSA_KEYFILE_PUBLIC, DSA_KEYFILE_PRIVATE,
        NULL);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__ed25519_auth_ok(void)
{
    int rc;

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), ED25519_KEYFILE_PUBLIC, ED25519_KEYFILE_PRIVATE,
        NULL);

    cl_ssh2_check(rc);
}

int read_file(const char *path, char **buf, size_t *len);

void test_userauth_publickey__ed25519_mem_auth_ok(void)
{
    int rc;
    char *buffer = NULL;
    size_t len = 0;

    cl_userauth_check_mech(session, USERNAME, "publickey");

    if(read_file(ED25519_KEYFILE_PRIVATE, &buffer, &len)) {
        cl_fail("Reading key file failed");
    }

    rc = libssh2_userauth_publickey_frommemory(session, USERNAME, strlen(USERNAME),
                                               NULL, 0, buffer, len, NULL);

    free(buffer);

    cl_ssh2_check(rc);
}

int read_file(const char *path, char **out_buffer, size_t *out_len)
{
    FILE *fp = NULL;
    char *buffer = NULL;
    size_t len = 0;

    if(out_buffer == NULL || out_len == NULL || path == NULL) {
        fprintf(stderr, "invalid params.");
        return 1;
    }

    *out_buffer = NULL;
    *out_len = 0;

    fp = fopen(path, "r");

    if(!fp) {
       fprintf(stderr, "File could not be read.");
       return 1;
    }

    fseek(fp, 0L, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    buffer = calloc(1, len + 1);
    if(!buffer) {
       fclose(fp);
       fprintf(stderr, "Could not alloc memory.");
       return 1;
    }

    if(1 != fread(buffer, len, 1, fp)) {
       fclose(fp);
       free(buffer);
       fprintf(stderr, "Could not read file into memory.");
       return 1;
    }

    fclose(fp);

    *out_buffer = buffer;
    *out_len = len;

    return 0;
}

void test_userauth_publickey__ed25519_encrypted_auth_ok(void)
{
    int rc;

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), ED25519_KEYFILE_ENC_PUBLIC,
        ED25519_KEYFILE_ENC_PRIVATE, ED25519_KEYFILE_PASSWORD);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__rsa_encrypted_auth_ok(void)
{
    int rc;

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), RSA_KEYFILE_ENC_PUBLIC,
        RSA_KEYFILE_ENC_PRIVATE, RSA_KEYFILE_PASSWORD);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__rsa_auth_ok(void)
{
    int rc;

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), RSA_KEYFILE_PUBLIC, RSA_KEYFILE_PRIVATE,
        NULL);

    cl_ssh2_check(rc);
}

void test_userauth_publickey__rsa_openssh_auth_ok(void)
{
    int rc;

    cl_userauth_check_mech(session, USERNAME, "publickey");

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, strlen(USERNAME), RSA_OPENSSH_KEYFILE_PUBLIC,
        RSA_OPENSSH_KEYFILE_PRIVATE, NULL);

    cl_ssh2_check(rc);
}
