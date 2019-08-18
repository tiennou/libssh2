#include "clar_libssh2.h"
#include "../userauth/userauth_helpers.h"
#include <libssh2_sftp.h>

#ifdef WIN32
#define __FILESIZE "I64"
#else
#define __FILESIZE "llu"
#endif

static LIBSSH2_SESSION *g_session = NULL;
static LIBSSH2_SFTP *g_sftp;

static LIBSSH2_SFTP *sftp_init(LIBSSH2_SESSION *session)
{
    LIBSSH2_SFTP *sftp;
    userauth_options opts = USERAUTH_OPTIONS_INIT;

    opts.password = OPENSSH_PASSWORD;
    cl_userauth_authenticate(session, OPENSSH_USERNAME, &opts);

    cl_ssh2_check_ptr_(sftp, session, libssh2_sftp_init(session));

    return sftp;
}

void test_sftp_sftp__initialize_blocking(void)
{
    cl_fixture_sandbox("sftp");

    g_session = cl_ssh2_open_session_openssh(NULL, 1);
    g_sftp = sftp_init(g_session);
}

void test_sftp_sftp__initialize_nonblocking(void)
{
    cl_fixture_sandbox("sftp");

    g_session = cl_ssh2_open_session_openssh(NULL, 0);
    g_sftp = sftp_init(g_session);
}

void test_sftp_sftp__cleanup(void)
{
    if(g_sftp) {
        cl_ssh2_check(libssh2_sftp_shutdown(g_sftp));
        g_sftp = NULL;
    }
    cl_ssh2_close_connected_session();

    cl_fixture_cleanup("sftp");
}

void test_sftp_sftp__readdir_ex(void)
{
    char filename[512];
    char longentry[512];
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int file_len;
    LIBSSH2_SFTP_HANDLE *handle;

    cl_ssh2_check_ptr(handle, libssh2_sftp_opendir(g_sftp, "sandbox/sftp"));

    cl_ssh2_check_while(file_len,
                        libssh2_sftp_readdir_ex(handle,
                                                filename, sizeof(filename),
                                                longentry, sizeof(longentry),
                                                &attrs), {
        if(longentry[0] != '\0') {
            printf("%s\n", longentry);
            continue;
        }

        if(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            /* this should check what permissions it
             is and print the output accordingly */
            printf("--fix----- ");
        }
        else {
            printf("---------- ");
        }

        if(attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
            printf("%4d %4d ", (int) attrs.uid, (int) attrs.gid);
        }
        else {
            printf("   -    - ");
        }

        if(attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
            printf("%8" __FILESIZE " ", attrs.filesize);
        }

        printf("%s\n", filename);
    });

    cl_ssh2_check(file_len);

    cl_ssh2_check(libssh2_sftp_closedir(handle));
}

void test_sftp_sftp__read_file(void)
{
    char buffer[4*1024];
    ssize_t read_len;
    size_t total_len = 0;
    LIBSSH2_SFTP_HANDLE *handle;
    char *sftp_path = "sandbox/" SFTP_FILE_SONGOF7CITIES;

    cl_ssh2_check_ptr(handle,
                      libssh2_sftp_open(g_sftp, sftp_path, LIBSSH2_FXF_READ,
                                        LIBSSH2_SFTP_S_IRWXU));

    cl_ssh2_check_while(read_len,
                        libssh2_sftp_read(handle, buffer, sizeof(buffer)), {
        total_len += read_len;
    });

    cl_ssh2_check(read_len);
    cl_assert_equal_i(2197, total_len);

    cl_ssh2_check(libssh2_sftp_close(handle));
}

void test_sftp_sftp__write_file(void)
{
    char buffer[4*1024], *ptr;
    char *written_data = NULL, *file_data = NULL;
    size_t data_len;
    size_t file_len;
    ssize_t read_len;
    size_t op_count = 0, total = 0;
    char *sftppath = "sandbox/sftp/writetest.txt";
    char *local_path = SFTP_FILE_SONGOF7CITIES;
    LIBSSH2_SFTP_HANDLE *handle;
    FILE *local;
    int err;

    local = fopen(local_path, "rb");
    cl_assert_(local != NULL, "Can't open local file");

    /* Open a writable file via SFTP */
    cl_ssh2_check_ptr(handle,
        libssh2_sftp_open(g_sftp, sftppath,
            LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|
            LIBSSH2_FXF_TRUNC,
            LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
            LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH));

    do {
        read_len = fread(buffer, 1, sizeof(buffer), local);
        if(read_len <= 0) {
            /* end of file */
            break;
        }
        ptr = buffer;
        total += read_len;

        do {
            /* write data in a loop until we block */
            cl_ssh2_check_(err, libssh2_sftp_write(handle, ptr, read_len));
            op_count++;
            if(err < 0)
                break;
            ptr += err;
            read_len -= err;

        } while(read_len);
    } while(err > 0);

    cl_ssh2_check(libssh2_sftp_close(handle));

    cl_ssh2_read_file(SFTP_FILE_SONGOF7CITIES, &file_data, &file_len);
    cl_ssh2_read_file("sftp/writetest.txt", &written_data, &data_len);
    cl_assert_equal_s(file_data, written_data);
    free(file_data);
    free(written_data);
}
