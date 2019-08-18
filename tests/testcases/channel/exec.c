#include "clar_libssh2.h"
#include <stdio.h>

static LIBSSH2_SESSION *g_session;

void test_channel_exec__initialize_blocking(void)
{
    g_session = cl_ssh2_open_session_openssh(NULL, 1);
}

void test_channel_exec__initialize_nonblocking(void)
{
    g_session = cl_ssh2_open_session_openssh(NULL, 0);
}

void test_channel_exec__cleanup(void)
{
    cl_ssh2_close_connected_session();
}

#define BUFSIZE 32000

void test_channel_exec__read(void)
{
    LIBSSH2_CHANNEL *channel;
    char *commandline = "echo hello";
    int exitcode;
    char *exitsignal = NULL;
    int bytecount = 0;

    /* Exec non-blocking on the remote host */
    cl_ssh2_check_ptr(channel, libssh2_channel_open_session(g_session));
    cl_ssh2_check(libssh2_channel_exec(channel, commandline));

    for(;;) {
        /* loop until we block */
        int rc;
        do {
            char buffer[0x4000];
            rc = libssh2_channel_read(channel, buffer, sizeof(buffer) );
            if(rc > 0) {
                int i;
                bytecount += rc;
                fprintf(stderr, "We read:\n");
                for(i = 0; i < rc; ++i)
                    fputc(buffer[i], stderr);
                fprintf(stderr, "\n");
            }
            else {
                if(rc != LIBSSH2_ERROR_EAGAIN)
                /* no need to output this for the EAGAIN case */
                    fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
            }
        }
        while(rc > 0);

        /* this is due to blocking that would occur otherwise so we loop on
         this condition */
        if(rc == LIBSSH2_ERROR_EAGAIN) {
            cl_ssh2_wait_socket();
        }
        else
            break;
    }

    exitcode = 127;
    cl_ssh2_check(libssh2_channel_close(channel));

    exitcode = libssh2_channel_get_exit_status(channel);
    libssh2_channel_get_exit_signal(channel, &exitsignal,
                                    NULL, NULL, NULL, NULL, NULL);

    cl_assert_equal_s("", exitsignal);

    libssh2_channel_free(channel);
    channel = NULL;
}

void test_channel_exec__readwrite(void)
{
    LIBSSH2_CHANNEL *channel;
    char *commandline = "echo hello";
    int exitcode;
    char *exitsignal = NULL;
    LIBSSH2_POLLFD fd;
    int running = 1;
    int bufsize = BUFSIZE;
    char buffer[BUFSIZE];
    int totsize = 1500000;
    int totwritten = 0;
    int totread = 0;
    int partials = 0;
    int rereads = 0;
    int rewrites = 0;

    /* Exec non-blocking on the remove host */
    cl_ssh2_check_ptr(channel, libssh2_channel_open_session(g_session));
    cl_ssh2_check(libssh2_channel_exec(channel, commandline));

    memset(buffer, 'A', sizeof(buffer));

    fd.type = LIBSSH2_POLLFD_CHANNEL;
    fd.fd.channel = channel;
    fd.events = LIBSSH2_POLLFD_POLLIN | LIBSSH2_POLLFD_POLLOUT;

    do {
        int rc = (libssh2_poll(&fd, 1, 10));
        int act = 0;

        if(rc < 1)
            continue;

        if(fd.revents & LIBSSH2_POLLFD_POLLIN) {
            int n = libssh2_channel_read(channel, buffer, sizeof(buffer));
            act++;

            if(n == LIBSSH2_ERROR_EAGAIN) {
                rereads++;
                fprintf(stderr, "will read again\n");
            }
            else if(n < 0) {
                fprintf(stderr, "read failed\n");
                exit(1);
            }
            else {
                totread += n;
                fprintf(stderr, "read %d bytes (%d in total)\n",
                        n, totread);
            }
        }

        if(fd.revents & LIBSSH2_POLLFD_POLLOUT) {
            act++;

            if(totwritten < totsize) {
                /* we have not written all data yet */
                int left = totsize - totwritten;
                int size = (left < bufsize) ? left : bufsize;
                int n = libssh2_channel_write_ex(channel, 0, buffer, size);

                if(n == LIBSSH2_ERROR_EAGAIN) {
                    rewrites++;
                    fprintf(stderr, "will write again\n");
                }
                else if(n < 0) {
                    fprintf(stderr, "write failed\n");
                    exit(1);
                }
                else {
                    totwritten += n;
                    fprintf(stderr, "wrote %d bytes (%d in total)",
                            n, totwritten);
                    if(left >= bufsize && n != bufsize) {
                        partials++;
                        fprintf(stderr, " PARTIAL");
                    }
                    fprintf(stderr, "\n");
                }
            }
            else {
                /* all data written, send EOF */
                rc = libssh2_channel_send_eof(channel);

                if(rc == LIBSSH2_ERROR_EAGAIN) {
                    fprintf(stderr, "will send eof again\n");
                }
                else if(rc < 0) {
                    fprintf(stderr, "send eof failed\n");
                    exit(1);
                }
                else {
                    fprintf(stderr, "sent eof\n");
                    /* we're done writing, stop listening for OUT events */
                    fd.events &= ~LIBSSH2_POLLFD_POLLOUT;
                }
            }
        }

        if(fd.revents & LIBSSH2_POLLFD_CHANNEL_CLOSED) {
            if(!act) /* don't leave loop until we have read all data */
                running = 0;
        }
    } while(running);

    exitcode = 127;
    cl_ssh2_check(libssh2_channel_close(channel));

    exitcode = libssh2_channel_get_exit_status(channel);
    libssh2_channel_get_exit_signal(channel, &exitsignal,
                                    NULL, NULL, NULL, NULL, NULL);

    cl_assert_equal_s("", exitsignal);

    libssh2_channel_free(channel);
    channel = NULL;
}
