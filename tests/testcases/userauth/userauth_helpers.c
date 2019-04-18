
#include "userauth_helpers.h"

void cl_userauth_check_mech(LIBSSH2_SESSION *session, const char *username, const char *mech)
{
	const char *userauth_list =
		libssh2_userauth_list(session, username, strlen(username));
	cl_assert_(userauth_list != NULL, "libssh2_userauth_list");

	if(strstr(userauth_list, mech) == NULL) {
		cl_fail_("'password' was expected in userauth list: %s",
				 userauth_list);
	}
}
