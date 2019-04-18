/* Copyright (C) 2016 Alexander Lamaison
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "clar_libssh2.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <limits.h>

static int run_command_varg(char **output, const char *command, va_list args)
{
    FILE *pipe;
    char command_buf[BUFSIZ];
    char buf[BUFSIZ];
    char *p;
    int ret;
    if(output) {
        *output = NULL;
    }

    /* Format the command string */
    ret = vsnprintf(command_buf, sizeof(command_buf), command, args);
    if(ret < 0 || ret >= BUFSIZ) {
        fprintf(stderr, "Unable to format command (%s)\n", command);
        return -1;
    }

    /* Rewrite the command to redirect stderr to stdout to we can output it */
    if(strlen(command_buf) + 6 >= sizeof(command_buf)) {
        fprintf(stderr, "Unable to rewrite command (%s)\n", command);
        return -1;
    }

    strncat(command_buf, " 2>&1", 6);

#ifdef WIN32
    pipe = _popen(command_buf, "r");
#else
    pipe = popen(command_buf, "r");
#endif
    if(!pipe) {
        fprintf(stderr, "Unable to execute command '%s'\n", command);
        return -1;
    }
    p = buf;
    while(fgets(p, sizeof(buf) - (p - buf), pipe) != NULL)
        ;

#ifdef WIN32
    ret = _pclose(pipe);
#else
    ret = pclose(pipe);
#endif
    if(ret != 0) {
        fprintf(stderr, "Error running command '%s' (exit %d): %s\n",
                command, ret, buf);
    }

    if(output) {
        /* command output may contain a trailing newline, so we trim
         * whitespace here */
        size_t end = strlen(buf) - 1;
        while(end > 0 && isspace(buf[end])) {
            buf[end] = '\0';
        }

        *output = strdup(buf);
    }
    return ret;
}

static int run_command(char **output, const char *command, ...)
{
    va_list args;
    int ret;

    va_start(args, command);
    ret = run_command_varg(output, command, args);
    va_end(args);

    return ret;
}

static int build_openssh_server_docker_image()
{
    return run_command(NULL, "docker build -t libssh2/openssh_server openssh_server");
}

static int start_openssh_server(char **container_id_out)
{
    return run_command(container_id_out,
                       "docker run --detach -P libssh2/openssh_server"
                       );
}

static int stop_openssh_server(char *container_id)
{
    return run_command(NULL, "docker stop %s", container_id);
}

static const char *docker_machine_name()
{
    return getenv("DOCKER_MACHINE_NAME");
}

static int ip_address_from_container(char *container_id, char **ip_address_out)
{
    const char *active_docker_machine = docker_machine_name();
    if(active_docker_machine != NULL) {

        /* This can be flaky when tests run in parallel (see
           https://github.com/docker/machine/issues/2612), so we retry a few
           times with exponential backoff if it fails */
        int attempt_no = 0;
        int wait_time = 500;
        for(;;) {
            return run_command(ip_address_out, "docker-machine ip %s", active_docker_machine);

            if(attempt_no > 5) {
                fprintf(
                    stderr,
                    "Unable to get IP from docker-machine after %d attempts\n",
                    attempt_no);
                return -1;
            }
            else {
#ifdef WIN32
#pragma warning(push)
#pragma warning(disable : 4996)
                _sleep(wait_time);
#pragma warning(pop)
#else
                sleep(wait_time);
#endif
                ++attempt_no;
                wait_time *= 2;
            }
        }
    }
    else {
        return run_command(ip_address_out,
                           "docker inspect --format "
                           "\"{{ index (index (index .NetworkSettings.Ports "
                           "\\\"22/tcp\\\") 0) \\\"HostIp\\\" }}\" %s",
                           container_id);
    }
}

static int port_from_container(char *container_id, char **port_out)
{
    return run_command(port_out,
                       "docker inspect --format "
                       "\"{{ index (index (index .NetworkSettings.Ports "
                       "\\\"22/tcp\\\") 0) \\\"HostPort\\\" }}\" %s",
                       container_id);
}

static int open_socket_to_container(char *container_id)
{
    char *ip_address = NULL;
    char *port_string = NULL;
    unsigned long hostaddr;
    int sock;
    struct sockaddr_in sin;

    int ret = ip_address_from_container(container_id, &ip_address);
    if(ret != 0) {
        fprintf(stderr, "Failed to get IP address for container %s\n", container_id);
        ret = -1;
        goto cleanup;
    }

    ret = port_from_container(container_id, &port_string);
    if(ret != 0) {
        fprintf(stderr, "Failed to get port for container %s\n", container_id);
        ret = -1;
    }

    hostaddr = inet_addr(ip_address);
    if(hostaddr == (unsigned long)(-1)) {
        fprintf(stderr, "Failed to convert %s host address\n", ip_address);
        ret = -1;
        goto cleanup;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock <= 0) {
        fprintf(stderr, "Failed to open socket (%d)\n", sock);
        ret = -1;
        goto cleanup;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons((short)strtol(port_string, NULL, 0));
    sin.sin_addr.s_addr = hostaddr;

    if(connect(sock, (struct sockaddr *)(&sin),
               sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "Failed to connect to %s:%s\n", ip_address, port_string);
        ret = -1;
        goto cleanup;
    }

    ret = sock;

cleanup:
    free(ip_address);
    free(port_string);

    return ret;
}

static char *running_container_id = NULL;

int cl_ssh2_start_openssh_fixture(void)
{
    int ret;
#ifdef HAVE_WINSOCK2_H
    WSADATA wsadata;

    ret = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(ret != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", ret);
        return 1;
    }
#endif

	const char *openssh_server = cl_fixture("openssh_server");
	ret = run_command(NULL, "cp -R \"%s\" \"%s\"", openssh_server,
		clar_sandbox_path());
	if(ret != 0) {
		fprintf(stderr, "Failed to copy openssh_server directory\n");
		return ret;
	}

    ret = build_openssh_server_docker_image();
    if(ret != 0) {
        fprintf(stderr, "Failed to build docker image\n");
        return ret;
    }
	return start_openssh_server(&running_container_id);
}

void cl_ssh2_stop_openssh_fixture(void)
{
    if(running_container_id) {
        stop_openssh_server(running_container_id);
        free(running_container_id);
        running_container_id = NULL;
    }
    else {
        fprintf(stderr, "Cannot stop container - none started");
    }
}

int open_socket_to_openssh_server()
{
    return open_socket_to_container(running_container_id);
}


LIBSSH2_SESSION *connected_session = NULL;
int connected_socket = -1;

static int connect_to_server()
{
    connected_socket = open_socket_to_openssh_server();
    if(connected_socket <= 0) {
        return -1;
    }

    return libssh2_session_handshake(connected_session, connected_socket);
}

LIBSSH2_SESSION *cl_ssh2_connect_openssh_session(void *abstract)
{
    connected_session = libssh2_session_init_ex(NULL, NULL, NULL, abstract);
	if(!connected_session)
		cl_fail_("failed to initialize session: %s", cl_ssh2_last_error());

    libssh2_session_set_blocking(connected_session, 1);

	cl_ssh2_check(connect_to_server());

    return connected_session;
}

const char *cl_ssh2_last_error(void)
{
	static char *message;
    if(connected_session) {
        int rc =
            libssh2_session_last_error(connected_session, &message, NULL, 0);
		if(rc == 0) {
			message = "No last error";
		}
    }
    else {
		message = "No session";
    }
	return message;
}

void cl_ssh2_close_connected_session(void)
{
    if(connected_session) {
        libssh2_session_disconnect(connected_session, "test ended");
        libssh2_session_free(connected_session);
        shutdown(connected_socket, 2);
        connected_session = NULL;
    }
    else {
        fprintf(stderr, "Cannot stop session - none started");
    }
}
