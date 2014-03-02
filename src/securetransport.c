/* Copyright (C) 2013 Keith Duncan */

#import "securetransport.h"

#include "libssh2_priv.h"

#pragma mark RSA

int _libssh2_rsa_free(libssh2_rsa_ctx *rsa) {
  CFRelease(rsa);
  return 0;
}

/*
    Create an RSA private key from the raw numeric components.

    rsa - Out parameter, should be populated on successful return.
    e, n, d, p, q, e1, e2, coeff - Positive integer in big-endian form.

    Returns 0 if the key is created, 1 otherwise.
*/
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
                     const unsigned char *coeffdata,
                     unsigned long coefflen) {
  assert(rsa != NULL);
  assert(edata != NULL);
  assert(ndata != NULL);
  assert(ddata != NULL);
  assert(pdata != NULL);
  assert(qdata != NULL);
  assert(e1data != NULL);
  assert(e2data != NULL);
  assert(e2data != NULL);
  assert(coeffdata != NULL);

  return 0;
}

/*
    Create an RSA private key from a file.

    Should support PKCS#1 and PKCS#8 keys, both encrypted and unencrypted.
    PKCS#8 keys may be PEM or DER encoded.
 
    rsa        - Out parameter, should be populated on successful return.
    session    - Non-NULL when invoked from libssh2.
    filename   - nul terminated C string, path to the private key file.
    passphrase - nul terminated C string, may be NULL, not covariant with
                 whether the private key is encrypted.

    Returns 0 if the key is created, 1 otherwise.
*/
int _libssh2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                             LIBSSH2_SESSION * session,
                             const char *filename,
                             unsigned const char *passphrase) {
  assert(rsa != NULL);
  assert(filename != NULL);

  return 0;
}

/*
    Verify an RSA signature with an RSA key.
    
    rsa     - Initialised RSA key, non NULL.
    sig     - Binary data, non NULL.
    sig_len - Length of sig, non zero.
    m       - Binary message, non NULL.
    m_len   - Length of m, non zero.
 
    Returns 0 if the signature is valid, 1 otherwise.
 */
int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsa,
                             const unsigned char *sig,
                             unsigned long sig_len,
                             const unsigned char *m,
                             unsigned long m_len) {
  assert(rsa != NULL);
  assert(sig != NULL);
  assert(m != NULL);

  return 0;
}

/*
    Sign a SHA1 hash with an RSA key.
 
    session       - In, non NULL when invoked from libssh2.
    rsa           - Initialised RSA key, non NULL.
    hash          - In parameter, SHA1 hash bytes.
    hash_len      - In parameter, length of hash.
    signature     - Out parameter, malloced.
    signature_len - Out parameter, length of malloced signature.
 
    Returns 0 if the signature has been populated, 1 otherwise.
 */
int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                           libssh2_rsa_ctx * rsa,
                           const unsigned char *hash,
                           size_t hash_len,
                           unsigned char **signature,
                           size_t *signature_len) {
  return 0;
}

#pragma mark - DSA

int _libssh2_dsa_free(libssh2_dsa_ctx *dsa) {
  CFRelease(dsa);
  return 0;
}

/*
    Create a DSA private key from the raw numeric components.
  
    dsa - Out parameter, should be populated on successful return.
    p, q, g, y, x - Positive integer in big-endian form.
 
    Returns 0 if the key is created, 1 otherwise.
 */
int _libssh2_dsa_new(libssh2_dsa_ctx ** dsa,
                     const unsigned char *pdata,
                     unsigned long plen,
                     const unsigned char *qdata,
                     unsigned long qlen,
                     const unsigned char *gdata,
                     unsigned long glen,
                     const unsigned char *ydata,
                     unsigned long ylen,
                     const unsigned char *x,
                     unsigned long x_len) {
  return 0;
}

/*
    Create a DSA private key from a file.
 
    Keys can be encoded as FIPS186 or PKCS#8.
 
    dsa        - Out parameter, should be populated on successful return.
    session    - In parameter, non NULL when invoked from libssh2.
    filename   - nul terminated C string, path to the private key file.
    passphrase - nul terminated C string, may be NULL, not covariant with
                 whether the private key is encrypted.

    Returns 0 if the key is created, 1 otherwise.
 */
int _libssh2_dsa_new_private(libssh2_dsa_ctx ** dsa,
                             LIBSSH2_SESSION * session,
                             const char *filename,
                             unsigned const char *passphrase) {
  assert(dsa != NULL);
  assert(filename != NULL);
  return 0;
}

/*
    Verify a DSA signature with an DSA key.
    
    dsa     - Initialised DSA key, non NULL.
    sig     - Binary data, non NULL.
    m       - Binary message, non NULL.
    m_len   - Length of m, non zero.
 
    Returns 0 if the signature is valid, 1 otherwise.
 */
int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx * dsa,
                             const unsigned char *sig,
                             const unsigned char *m,
                             unsigned long m_len) {

  return 0;
}

/*
    Sign a SHA1 hash with a DSA key.

    dsa           - Initialised DSA key, non NULL.
    hash          - In parameter, SHA1 hash bytes.
    hash_len      - In parameter, length of hash.
    signature     - In parameter, pre malloced.
 
    Returns 0 if the signature has been populated, 1 otherwise.
 */
int _libssh2_dsa_sha1_sign(libssh2_dsa_ctx * dsa,
                           const unsigned char *hash,
                           unsigned long hash_len,
                           unsigned char *sig) {
  return 0;
}

#pragma mark - Ciphers

/*

 */
int _libssh2_cipher_init(_libssh2_cipher_ctx * h,
                         _libssh2_cipher_type(algo),
                         unsigned char *iv,
                         unsigned char *secret,
                         int encrypt) {
  assert(h != NULL);
  assert(iv != NULL);
  assert(secret != NULL);

  return 0;
}

/*
 
 */
int _libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                          _libssh2_cipher_type(algo),
                          int encrypt,
                          unsigned char *block,
                          size_t blocksize) {
  assert(ctx != NULL);
  assert(block != NULL);

  return 0;
}

void _libssh2_init_aes_ctr(void) {

}

#pragma mark - Private Public Keys

/*
    Extract public key from private key file.

    Used by libssh2 to provide a username + public key tuple to the server which
    if the server accepts will ask the client to sign data to prove it owns the
    corresponding private key.

    session        - In parameter, non NULL.
    method         - Out parameter, must be set upon successful return, one of
                     "ssh-rsa" and "ssh-dss" based on whether the public key is
                     RSA or DSA.
    method_len     - Out parameter, must be set upon successful return, the
                     length of the method string written out.
    pubkeydata     - Out parameter, must be set upon successful return. See
                     `gen_publickey_from_rsa` and `gen_publickey_from_dsa` for
                     the respective formats expected.
    pubkeydata_len - Out parameter, must be set upon successful return, the
                     length of the pubkeydata written out.
    privatekey     - File system path to the private key file, non NULL.
    passphrase     - Passphrase for the private key file, may be NULL. Not
                     covariant with whether the private key is encrypted.

    Returns 0 if the public key is created, 1 otherwise.
 */
int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              const char *privatekeyPath,
                              const char *passphrase) {
  assert(method != NULL);
  assert(method_len != NULL);
  assert(pubkeydata != NULL);
  assert(pubkeydata_len != NULL);
  assert(privatekeyPath != NULL);

  return 0;
}
