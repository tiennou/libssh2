/* Copyright (c) 2016, Art <https://github.com/wildart>
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

#include "libssh2_priv.h"

#ifdef LIBSSH2_MBEDTLS /* compile only if we build with mbedtls */

/*
 * This implementation should never be optimized out by the compiler
 *
 * This implementation was inspired from Colin Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * It uses a volatile function pointer to the standard memset(). Because the
 * pointer is volatile the compiler expects it to change at
 * any time and will not optimize out the call that could potentially perform
 * other operations on the input buffer instead of just setting it to 0.
 * Nevertheless, as pointed out by davidtgoldblatt on Hacker News
 * (refer to http://www.daemonology.net/blog/2014-09-05-erratum.html for
 * details), optimizations of the following form are still possible:
 *
 * if( memset_func != memset )
 *     memset_func( buf, 0, len );
 */
#ifdef LIBSSH2_CLEAR_MEMORY
static void * (* const volatile memset_func)(void *, int, size_t) = memset;
#endif

/*******************************************************************/
/*
 * mbedTLS backend: Global context handles
 */

static mbedtls_entropy_context  _libssh2_mbedtls_entropy;
static mbedtls_ctr_drbg_context _libssh2_mbedtls_ctr_drbg;

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

void
_libssh2_mbedtls_init(void)
{
    int ret;

    mbedtls_entropy_init(&_libssh2_mbedtls_entropy);
    mbedtls_ctr_drbg_init(&_libssh2_mbedtls_ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&_libssh2_mbedtls_ctr_drbg,
                                mbedtls_entropy_func,
                                &_libssh2_mbedtls_entropy, NULL, 0);
    if(ret != 0)
        mbedtls_ctr_drbg_free(&_libssh2_mbedtls_ctr_drbg);
}

void
_libssh2_mbedtls_free(void)
{
    mbedtls_ctr_drbg_free(&_libssh2_mbedtls_ctr_drbg);
    mbedtls_entropy_free(&_libssh2_mbedtls_entropy);
}

int
_libssh2_mbedtls_random(unsigned char *buf, int len)
{
    int ret;
    ret = mbedtls_ctr_drbg_random(&_libssh2_mbedtls_ctr_drbg, buf, len);
    return ret == 0 ? 0 : -1;
}

static void
_libssh2_mbedtls_safe_free(void *buf, int len)
{
#ifndef LIBSSH2_CLEAR_MEMORY
    (void)len;
#endif

    if(!buf)
        return;

#ifdef LIBSSH2_CLEAR_MEMORY
    if(len > 0)
        memset_func(buf, 0, len);
#endif

    mbedtls_free(buf);
}

int
_libssh2_mbedtls_cipher_init(_libssh2_cipher_ctx *ctx,
                             _libssh2_cipher_type(algo),
                             unsigned char *iv,
                             unsigned char *secret,
                             int encrypt)
{
    const mbedtls_cipher_info_t *cipher_info;
    int ret, op;

    if(!ctx)
        return -1;

    op = encrypt == 0 ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT;

    cipher_info = mbedtls_cipher_info_from_type(algo);
    if(!cipher_info)
        return -1;

    mbedtls_cipher_init(ctx);
    ret = mbedtls_cipher_setup(ctx, cipher_info);
    if(!ret)
        ret = mbedtls_cipher_setkey(ctx, secret, cipher_info->key_bitlen, op);

    if(!ret)
        ret = mbedtls_cipher_set_iv(ctx, iv, cipher_info->iv_size);

    return ret == 0 ? 0 : -1;
}

int
_libssh2_mbedtls_cipher_crypt(_libssh2_cipher_ctx *ctx,
                              _libssh2_cipher_type(algo),
                              int encrypt,
                              unsigned char *block,
                              size_t blocklen)
{
    int ret;
    unsigned char *output;
    size_t osize, olen, finish_olen;

    (void) encrypt;
    (void) algo;

    osize = blocklen + mbedtls_cipher_get_block_size(ctx);

    output = (unsigned char *)mbedtls_calloc(osize, sizeof(char));
    if(output) {
        ret = mbedtls_cipher_reset(ctx);

        if(!ret)
            ret = mbedtls_cipher_update(ctx, block, blocklen, output, &olen);

        if(!ret)
            ret = mbedtls_cipher_finish(ctx, output + olen, &finish_olen);

        if(!ret) {
            olen += finish_olen;
            memcpy(block, output, olen);
        }

        _libssh2_mbedtls_safe_free(output, osize);
    }
    else
        ret = -1;

    return ret == 0 ? 0 : -1;
}

void
_libssh2_mbedtls_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    mbedtls_cipher_free(ctx);
}


int
_libssh2_mbedtls_hash_init(mbedtls_md_context_t *ctx,
                          mbedtls_md_type_t mdtype,
                          const unsigned char *key, unsigned long keylen)
{
    const mbedtls_md_info_t *md_info;
    int ret, hmac;

    md_info = mbedtls_md_info_from_type(mdtype);
    if(!md_info)
        return 0;

    hmac = key == NULL ? 0 : 1;

    mbedtls_md_init(ctx);
    ret = mbedtls_md_setup(ctx, md_info, hmac);
    if(!ret) {
        if(hmac)
            ret = mbedtls_md_hmac_starts(ctx, key, keylen);
        else
            ret = mbedtls_md_starts(ctx);
    }

    return ret == 0 ? 1 : 0;
}

int
_libssh2_mbedtls_hash_final(mbedtls_md_context_t *ctx, unsigned char *hash)
{
    int ret;

    ret = mbedtls_md_finish(ctx, hash);
    mbedtls_md_free(ctx);

    return ret == 0 ? 0 : -1;
}

int
_libssh2_mbedtls_hash(const unsigned char *data, unsigned long datalen,
                      mbedtls_md_type_t mdtype, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info;
    int ret;

    md_info = mbedtls_md_info_from_type(mdtype);
    if(!md_info)
        return 0;

    ret = mbedtls_md(md_info, data, datalen, hash);

    return ret == 0 ? 0 : -1;
}

/*******************************************************************/
/*
 * mbedTLS backend: BigNumber functions
 */

_libssh2_bn *
_libssh2_mbedtls_bignum_init(void)
{
    _libssh2_bn *bignum;

    bignum = (_libssh2_bn *)mbedtls_calloc(1, sizeof(_libssh2_bn));
    if(bignum) {
        mbedtls_mpi_init(bignum);
    }

    return bignum;
}

void
_libssh2_mbedtls_bignum_free(_libssh2_bn *bn)
{
    if(bn) {
        mbedtls_mpi_free(bn);
        mbedtls_free(bn);
    }
}

static int
_libssh2_mbedtls_bignum_random(_libssh2_bn *bn, int bits, int top, int bottom)
{
    size_t len;
    int err;
    int i;

    if(!bn || bits <= 0)
        return -1;

    len = (bits + 7) >> 3;
    err = mbedtls_mpi_fill_random(bn, len, mbedtls_ctr_drbg_random,
                                  &_libssh2_mbedtls_ctr_drbg);
    if(err)
        return -1;

    /* Zero unused bits above the most significant bit*/
    for(i = len*8 - 1; bits <= i; --i) {
        err = mbedtls_mpi_set_bit(bn, i, 0);
        if(err)
            return -1;
    }

    /* If `top` is -1, the most significant bit of the random number can be
       zero.  If top is 0, the most significant bit of the random number is
       set to 1, and if top is 1, the two most significant bits of the number
       will be set to 1, so that the product of two such random numbers will
       always have 2*bits length.
    */
    for(i = 0; i <= top; ++i) {
        err = mbedtls_mpi_set_bit(bn, bits-i-1, 1);
        if(err)
            return -1;
    }

    /* make odd by setting first bit in least significant byte */
    if(bottom) {
        err = mbedtls_mpi_set_bit(bn, 0, 1);
        if(err)
            return -1;
    }

    return 0;
}


/*******************************************************************/
/*
 * mbedTLS backend: RSA functions
 */

int
_libssh2_mbedtls_rsa_new(libssh2_rsa_ctx **rsa,
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
                        unsigned long coefflen)
{
    int ret;
    libssh2_rsa_ctx *ctx;

    ctx = (libssh2_rsa_ctx *) mbedtls_calloc(1, sizeof(libssh2_rsa_ctx));
    if(ctx != NULL) {
        mbedtls_rsa_init(ctx, MBEDTLS_RSA_PKCS_V15, 0);
    }
    else
        return -1;

    /* !checksrc! disable ASSIGNWITHINCONDITION 1 */
    if((ret = mbedtls_mpi_read_binary(&(ctx->E), edata, elen) ) != 0 ||
       (ret = mbedtls_mpi_read_binary(&(ctx->N), ndata, nlen) ) != 0) {
        ret = -1;
    }

    if(!ret) {
        ctx->len = mbedtls_mpi_size(&(ctx->N));
    }

    if(!ret && ddata) {
        /* !checksrc! disable ASSIGNWITHINCONDITION 1 */
        if((ret = mbedtls_mpi_read_binary(&(ctx->D), ddata, dlen) ) != 0 ||
           (ret = mbedtls_mpi_read_binary(&(ctx->P), pdata, plen) ) != 0 ||
           (ret = mbedtls_mpi_read_binary(&(ctx->Q), qdata, qlen) ) != 0 ||
           (ret = mbedtls_mpi_read_binary(&(ctx->DP), e1data, e1len) ) != 0 ||
           (ret = mbedtls_mpi_read_binary(&(ctx->DQ), e2data, e2len) ) != 0 ||
           (ret = mbedtls_mpi_read_binary(&(ctx->QP), coeffdata, coefflen) )
           != 0) {
            ret = -1;
        }
        ret = mbedtls_rsa_check_privkey(ctx);
    }
    else if(!ret) {
        ret = mbedtls_rsa_check_pubkey(ctx);
    }

    if(ret && ctx) {
        _libssh2_mbedtls_rsa_free(ctx);
        ctx = NULL;
    }
    *rsa = ctx;
    return ret;
}

int
_libssh2_mbedtls_rsa_new_private(libssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const unsigned char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;
    mbedtls_rsa_context *pk_rsa;

    *rsa = (libssh2_rsa_ctx *) LIBSSH2_ALLOC(session, sizeof(libssh2_rsa_ctx));
    if(*rsa == NULL)
        return -1;

    mbedtls_rsa_init(*rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_pk_init(&pkey);

    ret = mbedtls_pk_parse_keyfile(&pkey, filename, (char *)passphrase);
    if(ret != 0 || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pkey);
        mbedtls_rsa_free(*rsa);
        LIBSSH2_FREE(session, *rsa);
        *rsa = NULL;
        return -1;
    }

    pk_rsa = mbedtls_pk_rsa(pkey);
    mbedtls_rsa_copy(*rsa, pk_rsa);
    mbedtls_pk_free(&pkey);

    return 0;
}

int
_libssh2_mbedtls_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           unsigned const char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;
    mbedtls_rsa_context *pk_rsa;
    void *filedata_nullterm;
    size_t pwd_len;

    *rsa = (libssh2_rsa_ctx *) mbedtls_calloc(1, sizeof(libssh2_rsa_ctx));
    if(*rsa == NULL)
        return -1;

    /*
    mbedtls checks in "mbedtls/pkparse.c:1184" if "key[keylen - 1] != '\0'"
    private-key from memory will fail if the last byte is not a null byte
    */
    filedata_nullterm = mbedtls_calloc(filedata_len + 1, 1);
    if(filedata_nullterm == NULL) {
        return -1;
    }
    memcpy(filedata_nullterm, filedata, filedata_len);

    mbedtls_pk_init(&pkey);

    pwd_len = passphrase != NULL ? strlen((const char *)passphrase) : 0;
    ret = mbedtls_pk_parse_key(&pkey, (unsigned char *)filedata_nullterm,
                               filedata_len + 1,
                               passphrase, pwd_len);
    _libssh2_mbedtls_safe_free(filedata_nullterm, filedata_len);

    if(ret != 0 || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pkey);
        mbedtls_rsa_free(*rsa);
        LIBSSH2_FREE(session, *rsa);
        *rsa = NULL;
        return -1;
    }

    pk_rsa = mbedtls_pk_rsa(pkey);
    mbedtls_rsa_copy(*rsa, pk_rsa);
    mbedtls_pk_free(&pkey);

    return 0;
}

int
_libssh2_mbedtls_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    int ret;

    ret = _libssh2_mbedtls_hash(m, m_len, MBEDTLS_MD_SHA1, hash);
    if(ret)
        return -1; /* failure */

    ret = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                   MBEDTLS_MD_SHA1, SHA_DIGEST_LENGTH,
                                   hash, sig);

    return (ret == 0) ? 0 : -1;
}

int
_libssh2_mbedtls_rsa_sha1_sign(LIBSSH2_SESSION *session,
                              libssh2_rsa_ctx *rsa,
                              const unsigned char *hash,
                              size_t hash_len,
                              unsigned char **signature,
                              size_t *signature_len)
{
    int ret;
    unsigned char *sig;
    unsigned int sig_len;

    (void)hash_len;

    sig_len = rsa->len;
    sig = LIBSSH2_ALLOC(session, sig_len);
    if(!sig) {
        return -1;
    }

    ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE,
                                 MBEDTLS_MD_SHA1, SHA_DIGEST_LENGTH,
                                 hash, sig);
    if(ret) {
        LIBSSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = sig_len;

    return (ret == 0) ? 0 : -1;
}

void
_libssh2_mbedtls_rsa_free(libssh2_rsa_ctx *ctx)
{
    mbedtls_rsa_free(ctx);
    mbedtls_free(ctx);
}

static unsigned char *
gen_publickey_from_rsa(LIBSSH2_SESSION *session,
                      mbedtls_rsa_context *rsa,
                      size_t *keylen)
{
    int            e_bytes, n_bytes;
    unsigned long  len;
    unsigned char *key;
    unsigned char *p;

    e_bytes = mbedtls_mpi_size(&rsa->E);
    n_bytes = mbedtls_mpi_size(&rsa->N);

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

    key = LIBSSH2_ALLOC(session, len);
    if(!key) {
        return NULL;
    }

    /* Process key encoding. */
    p = key;

    _libssh2_htonu32(p, 7);  /* Key type. */
    p += 4;
    memcpy(p, "ssh-rsa", 7);
    p += 7;

    _libssh2_htonu32(p, e_bytes);
    p += 4;
    mbedtls_mpi_write_binary(&rsa->E, p, e_bytes);

    _libssh2_htonu32(p, n_bytes);
    p += 4;
    mbedtls_mpi_write_binary(&rsa->N, p, n_bytes);

    *keylen = (size_t)(p - key);
    return key;
}

static int
_libssh2_mbedtls_pub_priv_key(LIBSSH2_SESSION *session,
                               unsigned char **method,
                               size_t *method_len,
                               unsigned char **pubkeydata,
                               size_t *pubkeydata_len,
                               mbedtls_pk_context *pkey)
{
    unsigned char *key = NULL, *mth = NULL;
    size_t keylen = 0, mthlen = 0;
    int ret;
    mbedtls_rsa_context *rsa;

    if(mbedtls_pk_get_type(pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(pkey);
        return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                              "Key type not supported");
    }

    /* write method */
    mthlen = 7;
    mth = LIBSSH2_ALLOC(session, mthlen);
    if(mth) {
        memcpy(mth, "ssh-rsa", mthlen);
    }
    else {
        ret = -1;
    }

    rsa = mbedtls_pk_rsa(*pkey);
    key = gen_publickey_from_rsa(session, rsa, &keylen);
    if(key == NULL) {
        ret = -1;
    }

    /* write output */
    if(ret) {
        if(mth)
            LIBSSH2_FREE(session, mth);
        if(key)
            LIBSSH2_FREE(session, key);
    }
    else {
        *method = mth;
        *method_len = mthlen;
        *pubkeydata = key;
        *pubkeydata_len = keylen;
    }

    return ret;
}

int
_libssh2_mbedtls_pub_priv_keyfile(LIBSSH2_SESSION *session,
                                 unsigned char **method,
                                 size_t *method_len,
                                 unsigned char **pubkeydata,
                                 size_t *pubkeydata_len,
                                 const char *privatekey,
                                 const char *passphrase)
{
    mbedtls_pk_context pkey;
    char buf[1024];
    int ret;

    mbedtls_pk_init(&pkey);
    ret = mbedtls_pk_parse_keyfile(&pkey, privatekey, passphrase);
    if(ret != 0) {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return _libssh2_error(session, LIBSSH2_ERROR_FILE, buf);
    }

    ret = _libssh2_mbedtls_pub_priv_key(session, method, method_len,
                                       pubkeydata, pubkeydata_len, &pkey);

    mbedtls_pk_free(&pkey);

    return ret;
}

int
_libssh2_mbedtls_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                       unsigned char **method,
                                       size_t *method_len,
                                       unsigned char **pubkeydata,
                                       size_t *pubkeydata_len,
                                       const char *privatekeydata,
                                       size_t privatekeydata_len,
                                       const char *passphrase)
{
    mbedtls_pk_context pkey;
    char buf[1024];
    int ret;
    void *privatekeydata_nullterm;
    size_t pwd_len;

    /*
    mbedtls checks in "mbedtls/pkparse.c:1184" if "key[keylen - 1] != '\0'"
    private-key from memory will fail if the last byte is not a null byte
    */
    privatekeydata_nullterm = mbedtls_calloc(privatekeydata_len + 1, 1);
    if(privatekeydata_nullterm == NULL) {
        return -1;
    }
    memcpy(privatekeydata_nullterm, privatekeydata, privatekeydata_len);

    mbedtls_pk_init(&pkey);

    pwd_len = passphrase != NULL ? strlen((const char *)passphrase) : 0;
    ret = mbedtls_pk_parse_key(&pkey,
                               (unsigned char *)privatekeydata_nullterm,
                               privatekeydata_len + 1,
                               (const unsigned char *)passphrase, pwd_len);
    _libssh2_mbedtls_safe_free(privatekeydata_nullterm, privatekeydata_len);

    if(ret != 0) {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return _libssh2_error(session, LIBSSH2_ERROR_FILE, buf);
    }

    ret = _libssh2_mbedtls_pub_priv_key(session, method, method_len,
                                       pubkeydata, pubkeydata_len, &pkey);

    mbedtls_pk_free(&pkey);

    return ret;
}

void _libssh2_init_aes_ctr(void)
{
    /* no implementation */
}


/*******************************************************************/
/*
 * mbedTLS backend: Diffie-Hellman functions
 */

void
_libssh2_dh_init(_libssh2_dh_ctx *dhctx)
{
    *dhctx = _libssh2_mbedtls_bignum_init();    /* Random from client */
}

int
_libssh2_dh_key_pair(_libssh2_dh_ctx *dhctx, _libssh2_bn *public,
                     _libssh2_bn *g, _libssh2_bn *p, int group_order)
{
    /* Generate x and e */
    _libssh2_mbedtls_bignum_random(*dhctx, group_order * 8 - 1, 0, -1);
    mbedtls_mpi_exp_mod(public, g, *dhctx, p, NULL);
    return 0;
}

int
_libssh2_dh_secret(_libssh2_dh_ctx *dhctx, _libssh2_bn *secret,
                   _libssh2_bn *f, _libssh2_bn *p)
{
    /* Compute the shared secret */
    mbedtls_mpi_exp_mod(secret, f, *dhctx, p, NULL);
    return 0;
}

void
_libssh2_dh_dtor(_libssh2_dh_ctx *dhctx)
{
    _libssh2_mbedtls_bignum_free(*dhctx);
    *dhctx = NULL;
}

#if LIBSSH2_ECDSA

/*******************************************************************/
/*
 * mbedTLS backend: ECDSA functions
 */

#define LIBSSH2_MBEDTLS_CHECK(cond) \
{                                   \
    if(!(cond))                     \
        goto cleanup;               \
}

#define LIBSSH2_MBEDTLS_CHECK_RC(f) \
{                                   \
    rc = (f);                       \
    if(rc != 0)                     \
        goto cleanup;               \
}

#define LIBSSH2_MBEDTLS_RETURN_ERROR(errno)             \
{                                                       \
    if(rc != 0) {                                       \
        char buf[1024];                                 \
        mbedtls_strerror(rc, (char *)buf, sizeof(buf)); \
        return _libssh2_error(session, errno, buf);     \
    }                                                   \
}

/*
 * _libssh2_ecdsa_create_key
 *
 * Creates a local private key based on input curve
 * and returns octal value and octal length
 *
 */

int
_libssh2_mbedtls_ecdsa_create_key(LIBSSH2_SESSION *session,
                                  _libssh2_ec_key **privkey,
                                  unsigned char **pubkey_oct,
                                  size_t *pubkey_oct_len,
                                  libssh2_curve_type curve)
{
    size_t plen = 0;
    int rc;

    LIBSSH2_MBEDTLS_CHECK(privkey);
    LIBSSH2_MBEDTLS_CHECK(pubkey_oct);
    LIBSSH2_MBEDTLS_CHECK(pubkey_oct_len);

    LIBSSH2_MBEDTLS_CHECK
    (*privkey = LIBSSH2_ALLOC(session, sizeof(mbedtls_ecp_keypair)));

    mbedtls_ecdsa_init(*privkey);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecdsa_genkey(*privkey, (mbedtls_ecp_group_id)curve,
                          mbedtls_ctr_drbg_random,
                          &_libssh2_mbedtls_ctr_drbg));

    plen        = 2 * mbedtls_mpi_size(&(*privkey)->grp.P) + 1;
    *pubkey_oct = LIBSSH2_ALLOC(session, plen);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecp_point_write_binary(&(*privkey)->grp, &(*privkey)->Q,
                                    MBEDTLS_ECP_PF_UNCOMPRESSED,
                                    pubkey_oct_len, *pubkey_oct, plen));

    return 0;

cleanup:

    _libssh2_mbedtls_ecdsa_free(*privkey);
    _libssh2_mbedtls_safe_free(*pubkey_oct, plen);
    *privkey = NULL;

    return -1;
}

/* _libssh2_ecdsa_curve_name_with_octal_new
 *
 * Creates a new public key given an octal string, length and type
 *
 */

int
_libssh2_mbedtls_ecdsa_curve_name_with_octal_new(libssh2_ecdsa_ctx **ctx,
                                                 const unsigned char *k,
                                                 size_t k_len,
                                                 libssh2_curve_type curve)
{
    int rc;

    LIBSSH2_MBEDTLS_CHECK(ctx);

    LIBSSH2_MBEDTLS_CHECK
    (*ctx = mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair)));

    mbedtls_ecdsa_init(*ctx);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecp_group_load(&(*ctx)->grp, (mbedtls_ecp_group_id)curve));

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecp_point_read_binary(&(*ctx)->grp, &(*ctx)->Q, k, k_len));

    return 0;

cleanup:

    _libssh2_mbedtls_ecdsa_free(*ctx);
    *ctx = NULL;

    return -1;
}

/* _libssh2_ecdh_gen_k
 *
 * Computes the shared secret K given a local private key,
 * remote public key and length
 */

int
_libssh2_mbedtls_ecdh_gen_k(_libssh2_bn **k,
                            _libssh2_ec_key *privkey,
                            const unsigned char *server_pubkey,
                            size_t server_pubkey_len)
{
    mbedtls_ecp_point pubkey;
    int rc = -1;

    LIBSSH2_MBEDTLS_CHECK(k);

    mbedtls_ecp_point_init(&pubkey);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecp_point_read_binary(&privkey->grp, &pubkey,
                                   server_pubkey, server_pubkey_len));

    LIBSSH2_MBEDTLS_CHECK
    (*k = _libssh2_mbedtls_bignum_init());

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecdh_compute_shared(&privkey->grp, *k,
                                 &pubkey, &privkey->d,
                                 mbedtls_ctr_drbg_random,
                                 &_libssh2_mbedtls_ctr_drbg));

cleanup:

    mbedtls_ecp_point_free(&pubkey);

    return (rc == 0) ? 0 : -1;
}

#define LIBSSH2_MBEDTLS_ECDSA_VERIFY(digest_type)                         \
{                                                                         \
    size_t hash_len = SHA##digest_type##_DIGEST_LENGTH;                   \
    unsigned char hash[hash_len];                                         \
                                                                          \
    LIBSSH2_MBEDTLS_CHECK_RC                                              \
    (libssh2_sha##digest_type(m, m_len, hash));                           \
                                                                          \
    LIBSSH2_MBEDTLS_CHECK_RC                                              \
    (mbedtls_ecdsa_verify(&ctx->grp, hash, hash_len, &ctx->Q, &pr, &ps)); \
                                                                          \
}

/* _libssh2_ecdsa_sign
 *
 * Verifies the ECDSA signature of a hashed message
 *
 */

int
_libssh2_mbedtls_ecdsa_verify(libssh2_ecdsa_ctx *ctx,
                              const unsigned char *r, size_t r_len,
                              const unsigned char *s, size_t s_len,
                              const unsigned char *m, size_t m_len)
{
    mbedtls_mpi pr, ps;
    int rc = -1;

    mbedtls_mpi_init(&pr);
    mbedtls_mpi_init(&ps);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_mpi_read_binary(&pr, r, r_len));

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_mpi_read_binary(&ps, s, s_len));

    switch(_libssh2_ecdsa_get_curve_type(ctx)) {
    case LIBSSH2_EC_CURVE_NISTP256:
        LIBSSH2_MBEDTLS_ECDSA_VERIFY(256);
        break;
    case LIBSSH2_EC_CURVE_NISTP384:
        LIBSSH2_MBEDTLS_ECDSA_VERIFY(384);
        break;
    case LIBSSH2_EC_CURVE_NISTP521:
        LIBSSH2_MBEDTLS_ECDSA_VERIFY(512);
        break;
    default:
        rc = -1;
    }

cleanup:

    mbedtls_mpi_free(&pr);
    mbedtls_mpi_free(&ps);

    return (rc == 0) ? 0 : -1;
}

static int
_libssh2_mbedtls_parse_eckey(libssh2_ecdsa_ctx **ctx,
                             mbedtls_pk_context *pkey,
                             LIBSSH2_SESSION *session,
                             const unsigned char *data,
                             size_t data_len,
                             const unsigned char *pwd)
{
    size_t pwd_len;
    int rc;

    pwd_len = pwd ? strlen((const char *) pwd) : 0;

    LIBSSH2_MBEDTLS_CHECK(ctx);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_pk_parse_key(pkey, data, data_len, pwd, pwd_len));

    LIBSSH2_MBEDTLS_CHECK
    (mbedtls_pk_get_type(pkey) == MBEDTLS_PK_ECKEY);

    LIBSSH2_MBEDTLS_CHECK
    (*ctx = LIBSSH2_ALLOC(session, sizeof(libssh2_ecdsa_ctx)));

    mbedtls_ecdsa_init(*ctx);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecdsa_from_keypair(*ctx, mbedtls_pk_ec(*pkey)));

    return 0;

cleanup:

    _libssh2_mbedtls_ecdsa_free(*ctx);
    *ctx = NULL;

    return -1;
}

static int
_libssh2_mbedtls_parse_openssh_key(libssh2_ecdsa_ctx **ctx,
                                   LIBSSH2_SESSION *session,
                                   const unsigned char *data,
                                   size_t data_len,
                                   const unsigned char *pwd)
{
    libssh2_curve_type type;
    unsigned char *name = NULL;
    struct string_buf *decrypted = NULL;
    size_t curvelen, exponentlen, pointlen;
    unsigned char *curve, *exponent, *point_buf;
    int rc = 0;

    LIBSSH2_MBEDTLS_CHECK_RC(
    _libssh2_openssh_pem_parse_memory(session, pwd,
                                      (const char *)data, data_len,
                                      &decrypted));

    LIBSSH2_MBEDTLS_CHECK_RC(
    _libssh2_get_string(decrypted, &name, NULL));

    LIBSSH2_MBEDTLS_CHECK_RC(
    _libssh2_mbedtls_ecdsa_curve_type_from_name((const char *)name, &type));

    LIBSSH2_MBEDTLS_CHECK_RC(
    _libssh2_get_string(decrypted, &curve, &curvelen));

    LIBSSH2_MBEDTLS_CHECK_RC(
    _libssh2_get_string(decrypted, &point_buf, &pointlen));

    LIBSSH2_MBEDTLS_CHECK_RC(
    _libssh2_get_bignum_bytes(decrypted, &exponent, &exponentlen));

    LIBSSH2_MBEDTLS_CHECK
    (*ctx = LIBSSH2_ALLOC(session, sizeof(libssh2_ecdsa_ctx)));

    mbedtls_ecdsa_init(*ctx);

    LIBSSH2_MBEDTLS_CHECK_RC(
    mbedtls_ecp_group_load(&(*ctx)->grp, (mbedtls_ecp_group_id)type));

    LIBSSH2_MBEDTLS_CHECK_RC(
    mbedtls_mpi_read_binary(&(*ctx)->d, exponent, exponentlen));

    LIBSSH2_MBEDTLS_CHECK_RC(
    mbedtls_ecp_check_privkey(&(*ctx)->grp, &(*ctx)->d));

    LIBSSH2_MBEDTLS_CHECK_RC(
    mbedtls_ecp_mul(&(*ctx)->grp, &(*ctx)->Q,
                    &(*ctx)->d, &(*ctx)->grp.G,
                    mbedtls_ctr_drbg_random,
                    &_libssh2_mbedtls_ctr_drbg));

    goto done;

cleanup:

    _libssh2_mbedtls_ecdsa_free(*ctx);
    *ctx = NULL;

done:

    if(decrypted)
        _libssh2_string_buf_free(session, decrypted);

    return rc;
}

/* _libssh2_ecdsa_new_private
 *
 * Creates a new private key given a file path and password
 *
 */

int
_libssh2_mbedtls_ecdsa_new_private(libssh2_ecdsa_ctx **ctx,
                                   LIBSSH2_SESSION *session,
                                   const char *filename,
                                   const unsigned char *pwd)
{
    mbedtls_pk_context pkey;
    unsigned char *data;
    size_t data_len;
    int rc = 0;

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_pk_load_file(filename, &data, &data_len));

    mbedtls_pk_init(&pkey);

    rc = _libssh2_mbedtls_parse_eckey(ctx, &pkey, session,
                                      data, data_len, pwd);

    if(rc == 0)
        goto cleanup;

    LIBSSH2_MBEDTLS_CHECK_RC
    (_libssh2_mbedtls_parse_openssh_key(ctx, session, data,
                                        data_len, pwd));

cleanup:

    mbedtls_pk_free(&pkey);

    _libssh2_mbedtls_safe_free(data, data_len);

    LIBSSH2_MBEDTLS_RETURN_ERROR(LIBSSH2_ERROR_FILE);

    return (*ctx == NULL) ? -1 : 0;
}

/* _libssh2_ecdsa_new_private
 *
 * Creates a new private key given a file data and password
 *
 */

int
_libssh2_mbedtls_ecdsa_new_private_frommemory(libssh2_ecdsa_ctx **ctx,
                                              LIBSSH2_SESSION *session,
                                              const char *data,
                                              size_t data_len,
                                              const unsigned char *pwd)
{
    unsigned char *ntdata;
    mbedtls_pk_context pkey;
    int rc = 0;

    mbedtls_pk_init(&pkey);

    LIBSSH2_MBEDTLS_CHECK
    (ntdata = LIBSSH2_ALLOC(session, data_len + 1));

    memcpy(ntdata, data, data_len);

    rc = _libssh2_mbedtls_parse_eckey(ctx, &pkey, session,
                                      ntdata, data_len + 1, pwd);

    if(rc == 0)
        goto cleanup;

    LIBSSH2_MBEDTLS_CHECK_RC
    (_libssh2_mbedtls_parse_openssh_key(ctx, session,
                                        ntdata, data_len + 1, pwd));

cleanup:

    mbedtls_pk_free(&pkey);

    _libssh2_mbedtls_safe_free(ntdata, data_len);

    LIBSSH2_MBEDTLS_RETURN_ERROR(LIBSSH2_ERROR_FILE);

    return (*ctx == NULL) ? -1 : 0;
}

static unsigned char *
_libssh2_mbedtls_mpi_write_binary(unsigned char *buf,
                                  const mbedtls_mpi *mpi,
                                  size_t bytes)
{
    unsigned char *p = buf;

    p += 4;
    *p = 0;

    mbedtls_mpi_write_binary(mpi, p + 1, bytes - 1);

    if(!(*(p + 1) & 0x80)) {
        memmove(p, p + 1, --bytes);
    }

    _libssh2_htonu32(p - 4, bytes);

    return p + bytes;
}

/* _libssh2_ecdsa_sign
 *
 * Computes the ECDSA signature of a previously-hashed message
 *
 */

int
_libssh2_mbedtls_ecdsa_sign(LIBSSH2_SESSION *session,
                            libssh2_ecdsa_ctx *ctx,
                            const unsigned char *hash,
                            unsigned long hash_len,
                            unsigned char **sign,
                            size_t *sign_len)
{
    size_t r_len, s_len, tmp_sign_len = 0;
    unsigned char *sp, *tmp_sign = NULL;
    mbedtls_mpi pr, ps;
    int rc;

    LIBSSH2_MBEDTLS_CHECK(sign);

    mbedtls_mpi_init(&pr);
    mbedtls_mpi_init(&ps);

    LIBSSH2_MBEDTLS_CHECK_RC
    (mbedtls_ecdsa_sign(&ctx->grp, &pr, &ps, &ctx->d,
                        hash, hash_len,
                        mbedtls_ctr_drbg_random,
                        &_libssh2_mbedtls_ctr_drbg));

    r_len = mbedtls_mpi_size(&pr) + 1;
    s_len = mbedtls_mpi_size(&ps) + 1;
    tmp_sign_len = r_len + s_len + 8;

    LIBSSH2_MBEDTLS_CHECK
    (tmp_sign = LIBSSH2_CALLOC(session, tmp_sign_len));

    sp = tmp_sign;
    sp = _libssh2_mbedtls_mpi_write_binary(sp, &pr, r_len);
    sp = _libssh2_mbedtls_mpi_write_binary(sp, &ps, s_len);

    *sign_len = (size_t)(sp - tmp_sign);

    LIBSSH2_MBEDTLS_CHECK
    (*sign = LIBSSH2_CALLOC(session, *sign_len));

    memcpy(*sign, tmp_sign, *sign_len);

cleanup:

    mbedtls_mpi_free(&pr);
    mbedtls_mpi_free(&ps);

    _libssh2_mbedtls_safe_free(tmp_sign, tmp_sign_len);

    return (*sign == NULL) ? -1 : 0;
}

/* _libssh2_ecdsa_get_curve_type
 *
 * returns key curve type that maps to libssh2_curve_type
 *
 */

libssh2_curve_type
_libssh2_mbedtls_ecdsa_get_curve_type(libssh2_ecdsa_ctx *ctx)
{
    return (libssh2_curve_type) ctx->grp.id;
}

/* _libssh2_ecdsa_curve_type_from_name
 *
 * returns 0 for success, key curve type that maps to libssh2_curve_type
 *
 */

int
_libssh2_mbedtls_ecdsa_curve_type_from_name(const char *name,
                                            libssh2_curve_type *out_type)
{
    int ret = 0;
    libssh2_curve_type type;

    if(name == NULL || strlen(name) != 19)
        return -1;

    if(strcmp(name, "ecdsa-sha2-nistp256") == 0)
        type = LIBSSH2_EC_CURVE_NISTP256;
    else if(strcmp(name, "ecdsa-sha2-nistp384") == 0)
        type = LIBSSH2_EC_CURVE_NISTP384;
    else if(strcmp(name, "ecdsa-sha2-nistp521") == 0)
        type = LIBSSH2_EC_CURVE_NISTP521;
    else {
        ret = -1;
    }

    if(ret == 0 && out_type) {
        *out_type = type;
    }

    return ret;
}

void
_libssh2_mbedtls_ecdsa_free(libssh2_ecdsa_ctx *ctx)
{
    mbedtls_ecdsa_free(ctx);
    mbedtls_free(ctx);
}

#endif /* LIBSSH2_ECDSA */
#endif /* LIBSSH2_MBEDTLS */
