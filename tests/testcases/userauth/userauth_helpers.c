
#include "userauth_helpers.h"

void cl_userauth_check_mech(LIBSSH2_SESSION *session, const char *username, const char *mech)
{
	const char *userauth_list =
		libssh2_userauth_list(session, username, strlen(username));
	if(userauth_list == NULL)
		cl_fail_("libssh2_userauth_list: %s", cl_ssh2_last_error());

	if(strstr(userauth_list, mech) == NULL) {
		cl_fail_("'%s' was expected in userauth list: %s",
				 mech, userauth_list);
	}
}
