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

#ifndef LIBSSH2_TESTS_CLAR_LIBSSH2_H
#define LIBSSH2_TESTS_CLAR_LIBSSH2_H

#include "clar.h"
#include "clar_libssh2_config.h"

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "libssh2_config.h"
#include <libssh2.h>

 /* configured in Dockerfile */
#define USERNAME "libssh2"
#define PASSWORD "my test password"

#define DSA_KEYFILE_PRIVATE "publickeys/key_dsa"
#define DSA_KEYFILE_PUBLIC "publickeys/key_dsa.pub"

#define RSA_KEYFILE_PRIVATE "publickeys/key_rsa"
#define RSA_KEYFILE_PUBLIC "publickeys/key_rsa.pub"

#define ED25519_KEYFILE_PRIVATE "publickeys/key_ed25519"
#define ED25519_KEYFILE_PUBLIC "publickeys/key_ed25519.pub"

#define ED25519_KEYFILE_ENC_PRIVATE "publickeys/key_ed25519_encrypted"
#define ED25519_KEYFILE_ENC_PUBLIC "publickeys/key_ed25519_encrypted.pub"
#define ED25519_KEYFILE_PASSWORD "libssh2"

#define RSA_KEYFILE_ENC_PRIVATE "publickeys/key_rsa_encrypted"
#define RSA_KEYFILE_ENC_PUBLIC "publickeys/key_rsa_encrypted.pub"
#define RSA_KEYFILE_PASSWORD "libssh2"

#define RSA_OPENSSH_KEYFILE_PRIVATE "publickeys/key_rsa_openssh"
#define RSA_OPENSSH_KEYFILE_PUBLIC "publickeys/key_rsa_openssh.pub"

#define WRONG_KEYFILE_PRIVATE "publickeys/key_dsa_wrong"
#define WRONG_KEYFILE_PUBLIC "publickeys/key_dsa_wrong.pub"


LIBSSH2_SESSION *cl_ssh2_connect_openssh_session(void *abstract);
void cl_ssh2_print_last_session_error(const char *function);
void cl_ssh2_close_connected_session(void);

int cl_ssh2_start_openssh_fixture(void);
void cl_ssh2_stop_openssh_fixture(void);

#define cl_fail_(msg, ...) cl_fail(msg)
#define cl_ssh2_check(expr) \
do { \
    if((expr) != 0) { \
        cl_fail("Unexpected failure"); \
    }\
} while (0);

#define cl_ssh2_fail(expected, expr, msg) \
do { \
    if(!(expr)) { \
        cl_fail((msg));\
    }\
    cl_assert_equal_i_((expected), (expr), msg); \
} while (0);

#endif
