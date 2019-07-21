#include "clar_libssh2.h"

static LIBSSH2_SESSION *g_session;

void test_channel_ssh__initialize(void)
{
    g_session = cl_ssh2_open_session_openssh(NULL, 1);
}

void test_channel_ssh__cleanup(void)
{
    cl_ssh2_close_connected_session();
}

void test_channel_ssh__basic(void)
{
    LIBSSH2_CHANNEL *channel;

    /* Request a shell */
    channel = libssh2_channel_open_session(g_session);
    if(!channel) {
        fprintf(stderr, "Unable to open a session\n");
        goto shutdown;
    }

    /* Some environment variables may be set,
     * It's up to the server which ones it'll allow though
     */
    libssh2_channel_setenv(channel, "FOO", "bar");

    /* Request a terminal with 'vanilla' terminal emulation
     * See /etc/termcap for more options
     */
    if(libssh2_channel_request_pty(channel, "vanilla")) {
        fprintf(stderr, "Failed requesting pty\n");
        goto skip_shell;
    }

    /* Open a SHELL on that pty */
    if(libssh2_channel_shell(channel)) {
        fprintf(stderr, "Unable to request shell on allocated pty\n");
        goto shutdown;
    }

    /* At this point the shell can be interacted with using
     * libssh2_channel_read()
     * libssh2_channel_read_stderr()
     * libssh2_channel_write()
     * libssh2_channel_write_stderr()
     *
     * Blocking mode may be (en|dis)abled with: libssh2_channel_set_blocking()
     * If the server send EOF, libssh2_channel_eof() will return non-0
     * To send EOF to the server use: libssh2_channel_send_eof()
     * A channel can be closed with: libssh2_channel_close()
     * A channel can be freed with: libssh2_channel_free()
     */

skip_shell:
    if(channel) {
        libssh2_channel_free(channel);
        channel = NULL;
    }

    /* Other channel types are supported via:
     * libssh2_scp_send()
     * libssh2_scp_recv2()
     * libssh2_channel_direct_tcpip()
     */

}
