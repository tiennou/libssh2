/* Copyright (C) 2013 Keith Duncan */

#import "securetransport.h"

#include "libssh2_priv.h"

#pragma mark - RSA

int _libssh2_rsa_new(libssh2_rsa_ctx ** rsa,
                     const unsigned char *edata,
                     unsigned long elen,
                     const unsigned char *ndata,
                     unsigned long nlen,
                     const unsigned char *ddata,
                     unsigned long dlen,
                     const unsigned char *pdata,
                     unsigned long plen,
                     const unsigned char *qdata,
                     unsigned long qlen,
                     const unsigned char *e1data,
                     unsigned long e1len,
                     const unsigned char *e2data,
                     unsigned long e2len,
                     const unsigned char *coeffdata, unsigned long coefflen) {
  return 0;
}

int _libssh2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                             LIBSSH2_SESSION * session,
                             const char *filename,
                             unsigned const char *passphrase) {
  return 0;
}

int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsa,
                             const unsigned char *sig,
                             unsigned long sig_len,
                             const unsigned char *m, unsigned long m_len) {
  return 0;
}

int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                           libssh2_rsa_ctx * rsactx,
                           const unsigned char *hash,
                           size_t hash_len,
                           unsigned char **signature,
                           size_t *signature_len) {
  return 0;
}

#pragma mark - DSA

int _libssh2_dsa_new(libssh2_dsa_ctx ** dsa,
                     const unsigned char *pdata,
                     unsigned long plen,
                     const unsigned char *qdata,
                     unsigned long qlen,
                     const unsigned char *gdata,
                     unsigned long glen,
                     const unsigned char *ydata,
                     unsigned long ylen,
                     const unsigned char *x, unsigned long x_len) {
  return 0;
}

int _libssh2_dsa_new_private(libssh2_dsa_ctx ** dsa,
                             LIBSSH2_SESSION * session,
                             const char *filename,
                             unsigned const char *passphrase) {
  return 0;
}

int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx * dsactx,
                             const unsigned char *sig,
                             const unsigned char *m, unsigned long m_len) {
  return 0;
}

int _libssh2_dsa_sha1_sign(libssh2_dsa_ctx * dsactx,
                           const unsigned char *hash,
                           unsigned long hash_len, unsigned char *sig) {
  return 0;
}

#pragma mark - Ciphers

int _libssh2_cipher_init(_libssh2_cipher_ctx * h,
                         _libssh2_cipher_type(algo),
                         unsigned char *iv,
                         unsigned char *secret, int encrypt) {
  return 0;
}

int _libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                          _libssh2_cipher_type(algo),
                          int encrypt, unsigned char *block, size_t blocksize) {
  return 0;
}

void _libssh2_init_aes_ctr(void) {

}

#pragma mark - Private Public Keys

int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session, unsigned char **method, size_t *method_len, unsigned char **pubkeydata, size_t *pubkeydata_len, const char *privatekey, const char *passphrase) {
  return 0;
}
