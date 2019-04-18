#ifndef LIBSSH2_TESTS_USERAUTH_HELPERS
#define LIBSSH2_TESTS_USERAUTH_HELPERS

#include "../../clar_libssh2.h"

void cl_userauth_check_mech(LIBSSH2_SESSION *session, const char *username, const char *mech);

#endif /* LIBSSH2_TESTS_USERAUTH_HELPERS */
