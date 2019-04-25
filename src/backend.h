/* Copyright (C) 2016, Etienne Samson
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

#ifndef LIBSSH2_BACKEND_H
#define LIBSSH2_BACKEND_H

/**
 * Definitions needed to implement a specific crypto library
 *
 * This document offers some hints about implementing a new crypto library
 * interface.
 *
 * A crypto library interface consists of at least a header file, defining
 * entities referenced from the libssh2 core modules.
 * Real code implementation (if needed), is left at the implementor's choice.
 *
 * This document lists the entities that must/may be defined in the header
 * file.
 *
 * Procedures listed as "void" may indeed have a result type: void indicates
 * the libssh2 core modules never use the function result.
 *
 * Unless otherwise indicated, those functions returns 0 to indicate failure.
 */

#define MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#define RIPEMD160_DIGEST_LENGTH 20

#define LIBSSH2_ED25519_KEY_LEN 32
#define LIBSSH2_ED25519_PRIVATE_KEY_LEN 64
#define LIBSSH2_ED25519_SIG_LEN 64

#define EC_MAX_POINT_LEN ((528 * 2 / 8) + 1)

void libssh2_crypto_init(void);
void libssh2_crypto_exit(void);

/* returns 0 in case of failure */
int _libssh2_random(void *buf, size_t len);

/* Digests */

int libssh2_sha1_init(libssh2_sha1_ctx *ctx);
int libssh2_sha1_update(libssh2_sha1_ctx ctx, const void *data, size_t len);
int libssh2_sha1_final(libssh2_sha1_ctx ctx, void *out);

int libssh2_sha256_init(libssh2_sha256_ctx *ctx);
int libssh2_sha256_update(libssh2_sha256_ctx ctx,
                          const void *data, size_t len);
int libssh2_sha256_final(libssh2_sha256_ctx ctx, void *out);

int libssh2_sha384_init(libssh2_sha384_ctx *ctx);
int libssh2_sha384_update(libssh2_sha384_ctx ctx,
                          const void *data, size_t len);
int libssh2_sha384_final(libssh2_sha384_ctx ctx, void *out);

int libssh2_sha512_init(libssh2_sha512_ctx *ctx);
int libssh2_sha512_update(libssh2_sha512_ctx ctx,
                          const void *data, size_t len);
int libssh2_sha512_final(libssh2_sha512_ctx ctx, void *out);

int libssh2_md5_init(libssh2_md5_ctx *ctx);
int libssh2_md5_update(libssh2_md5_ctx ctx, const void *data, size_t len);
int libssh2_md5_final(libssh2_md5_ctx ctx, void *out);

#define libssh2_hmac_ctx_init(...) /* deprecated */
int libssh2_hmac_sha1_init(libssh2_hmac_ctx *ctx,
                           const void *key, size_t keylen);
int libssh2_hmac_md5_init(libssh2_hmac_ctx *ctx,
                          const void *key, size_t keylen);
int libssh2_hmac_ripemd160_init(libssh2_hmac_ctx *ctx,
                                const void *key, size_t keylen);
int libssh2_hmac_sha256_init(libssh2_hmac_ctx *ctx,
                             const void *key, size_t keylen);
int libssh2_hmac_sha512_init(libssh2_hmac_ctx *ctx,
                             const void *key, size_t keylen);
int libssh2_hmac_update(libssh2_hmac_ctx ctx,
                        const void *data, size_t datalen);
int libssh2_hmac_final(libssh2_hmac_ctx ctx, void *data);
int libssh2_hmac_cleanup(libssh2_hmac_ctx *ctx);

/* Cipher */
int
_libssh2_cipher_init(_libssh2_cipher_ctx * h,
                     _libssh2_cipher_type(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt);
int
_libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                      _libssh2_cipher_type(algo),
                      int encrypt, unsigned char *block, size_t blklen);
void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx);

/* Bignum */
_libssh2_bn_ctx *_libssh2_bn_ctx_new(void);
void _libssh2_bn_ctx_free(_libssh2_bn_ctx *bnctx);

_libssh2_bn *_libssh2_bn_new(void);
_libssh2_bn *_libssh2_bn_new_from_bin(const void *val, size_t len);
int _libssh2_bn_to_bin(const _libssh2_bn *bn, void *data);
int _libssh2_bn_set_word(_libssh2_bn *bn, int32_t val);
size_t _libssh2_bn_bytes(const _libssh2_bn *bn);
size_t _libssh2_bn_bits(const _libssh2_bn *bn);
void _libssh2_bn_free(_libssh2_bn *bn);

/* DH */
void _libssh2_dh_init(_libssh2_dh_ctx *dhctx);
int _libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *public,
                                _libssh2_bn *g, _libssh2_bn *p,
                                int group_order,
                                _libssh2_bn_ctx *bnctx);
int _libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret,
                              _libssh2_bn *f, _libssh2_bn *p,
                              _libssh2_bn_ctx *bnctx);
void _libssh2_dh_dtor(_libssh2_dh_ctx *dhctx);

#if LIBSSH2_RSA
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
                     const unsigned char *coeffdata, unsigned long coefflen);
void _libssh2_rsa_free(libssh2_rsa_ctx *ctx);
int _libssh2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                             LIBSSH2_SESSION * session,
                             const char *filename,
                             unsigned const char *passphrase);
int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsa,
                             const unsigned char *sig,
                             unsigned long sig_len,
                             const unsigned char *m, unsigned long m_len);
int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                           libssh2_rsa_ctx * rsactx,
                           const unsigned char *hash,
                           size_t hash_len,
                           unsigned char **signature,
                           size_t *signature_len);
int _libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx ** rsa,
                                        LIBSSH2_SESSION * session,
                                        const char *filedata,
                                        size_t filedata_len,
                                        unsigned const char *passphrase);
#endif

#if LIBSSH2_DSA
int _libssh2_dsa_new(libssh2_dsa_ctx ** dsa,
                     const unsigned char *pdata,
                     unsigned long plen,
                     const unsigned char *qdata,
                     unsigned long qlen,
                     const unsigned char *gdata,
                     unsigned long glen,
                     const unsigned char *ydata,
                     unsigned long ylen,
                     const unsigned char *x, unsigned long x_len);
void _libssh2_dsa_free(libssh2_dsa_ctx *ctx);
int _libssh2_dsa_new_private(libssh2_dsa_ctx ** dsa,
                             LIBSSH2_SESSION * session,
                             const char *filename,
                             unsigned const char *passphrase);
int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx * dsactx,
                             const unsigned char *sig,
                             const unsigned char *m, unsigned long m_len);
int _libssh2_dsa_sha1_sign(libssh2_dsa_ctx * dsactx,
                           const unsigned char *hash,
                           unsigned long hash_len, unsigned char *sig);
int _libssh2_dsa_new_private_frommemory(libssh2_dsa_ctx ** dsa,
                                        LIBSSH2_SESSION * session,
                                        const char *filedata,
                                        size_t filedata_len,
                                        unsigned const char *passphrase);
#endif

#if LIBSSH2_ECDSA
int
_libssh2_ecdsa_curve_name_with_octal_new(libssh2_ecdsa_ctx ** ecdsactx,
                                         const unsigned char *k,
                                         size_t k_len,
                                         libssh2_curve_type type);
int
_libssh2_ecdsa_new_private(libssh2_ecdsa_ctx ** ec_ctx,
                           LIBSSH2_SESSION * session,
                           const char *filename,
                           unsigned const char *passphrase);

int
_libssh2_ecdsa_verify(libssh2_ecdsa_ctx * ctx,
                      const unsigned char *r, size_t r_len,
                      const unsigned char *s, size_t s_len,
                      const unsigned char *m, size_t m_len);

int
_libssh2_ecdsa_create_key(LIBSSH2_SESSION *session,
                          _libssh2_ec_key **out_private_key,
                          unsigned char **out_public_key_octal,
                          size_t *out_public_key_octal_len,
                          libssh2_curve_type curve_type);

int
_libssh2_ecdh_gen_k(_libssh2_bn **k, _libssh2_ec_key *private_key,
                    const unsigned char *server_public_key,
                    size_t server_public_key_len);

int
_libssh2_ecdsa_sign(LIBSSH2_SESSION *session, libssh2_ecdsa_ctx *ec_ctx,
                    const unsigned char *hash, unsigned long hash_len,
                    unsigned char **signature, size_t *signature_len);

int _libssh2_ecdsa_new_private_frommemory(libssh2_ecdsa_ctx ** ec_ctx,
                                          LIBSSH2_SESSION * session,
                                          const char *filedata,
                                          size_t filedata_len,
                                          unsigned const char *passphrase);

libssh2_curve_type
_libssh2_ecdsa_get_curve_type(libssh2_ecdsa_ctx *ec_ctx);


int
_libssh2_ecdsa_curve_type_from_name(const char *name,
                                    libssh2_curve_type *out_type);
#else
#define _libssh2_ec_key void
#define libssh2_curve_type void
#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519

int
_libssh2_curve25519_new(LIBSSH2_SESSION *session, libssh2_ed25519_ctx **ctx,
                        uint8_t **out_public_key, uint8_t **out_private_key);

int
_libssh2_curve25519_gen_k(_libssh2_bn **k,
                          uint8_t private_key[LIBSSH2_ED25519_KEY_LEN],
                          uint8_t server_public_key[LIBSSH2_ED25519_KEY_LEN]);

int
_libssh2_ed25519_verify(libssh2_ed25519_ctx *ctx, const uint8_t *s,
                        size_t s_len, const uint8_t *m, size_t m_len);

int
_libssh2_ed25519_new_private(libssh2_ed25519_ctx **ed_ctx,
                             LIBSSH2_SESSION *session,
                             const char *filename, const uint8_t *passphrase);

int
_libssh2_ed25519_new_public(libssh2_ed25519_ctx **ed_ctx,
                            LIBSSH2_SESSION *session,
                            const unsigned char *raw_pub_key,
                            const uint8_t key_len);

int
_libssh2_ed25519_sign(libssh2_ed25519_ctx *ctx, LIBSSH2_SESSION *session,
                      uint8_t **out_sig, size_t *out_sig_len,
                      const uint8_t *message, size_t message_len);

int
_libssh2_ed25519_new_private_frommemory(libssh2_ed25519_ctx **ed_ctx,
                                        LIBSSH2_SESSION *session,
                                        const char *filedata,
                                        size_t filedata_len,
                                        unsigned const char *passphrase);

#endif /* LIBSSH2_ED25519 */

int _libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              const char *privatekey,
                              const char *passphrase);

int _libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                    unsigned char **method,
                                    size_t *method_len,
                                    unsigned char **pubkeydata,
                                    size_t *pubkeydata_len,
                                    const char *privatekeydata,
                                    size_t privatekeydata_len,
                                    const char *passphrase);

#endif /* LIBSSH2_BACKEND_H */
