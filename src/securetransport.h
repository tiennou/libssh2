/* Copyright (C) 2013 Keith Duncan */

#import <Security/Security.h>

#define _libssh2_random(buf, len) SecRandomCopyBytes(kSecRandomDefault, len, buf)

#define libssh2_sha1_ctx
#define libssh2_sha1_init(ctx)
#define libssh2_sha1_update(ctx, data, len)
#define libssh2_sha1_final(ctx, out)
void libssh2_sha1(const unsigned char *message, unsigned long len, unsigned char *out);

#define libssh2_md5_ctx
#define libssh2_md5_init(ctx)
#define libssh2_md5_update(ctx, data, len)
#define libssh2_md5_final(ctx, out)
void libssh2_md5(const unsigned char *message, unsigned long len, unsigned char *out);

#define libssh2_hmac_ctx
#define libssh2_hmac_sha1_init(ctx, key, keylen)
#define libssh2_hmac_md5_init(ctx, key, keylen)
#define libssh2_hmac_ripemd160_init(ctx, key, keylen)
#define libssh2_hmac_update(ctx, data, datalen)
#define libssh2_hmac_final(ctx, data)
#define libssh2_hmac_cleanup(ctx)

#define libssh2_crypto_init()
#define libssh2_crypto_exit()

#define libssh2_rsa_ctx
#define _libssh2_rsa_free(rsactx)

#define libssh2_dsa_ctx
#define _libssh2_dsa_free(dsactx)

#define _libssh2_cipher_type(name)
#define _libssh2_cipher_ctx

#define _libssh2_cipher_aes256
#define _libssh2_cipher_aes192
#define _libssh2_cipher_aes128

#ifdef HAVE_EVP_AES_128_CTR
#define _libssh2_cipher_aes128ctr
#define _libssh2_cipher_aes192ctr
#define _libssh2_cipher_aes256ctr
#else
#define _libssh2_cipher_aes128ctr
#define _libssh2_cipher_aes192ctr
#define _libssh2_cipher_aes256ctr
#endif

#define _libssh2_cipher_blowfish
#define _libssh2_cipher_arcfour
#define _libssh2_cipher_cast5
#define _libssh2_cipher_3des

#define _libssh2_cipher_dtor(ctx)

#define _libssh2_bn
#define _libssh2_bn_ctx
#define _libssh2_bn_ctx_new()
#define _libssh2_bn_ctx_free(bnctx)
#define _libssh2_bn_init()
#define _libssh2_bn_rand(bn, bits, top, bottom)
#define _libssh2_bn_mod_exp(r, a, p, m, ctx)
#define _libssh2_bn_set_word(bn, val)
#define _libssh2_bn_from_bin(bn, len, val)
#define _libssh2_bn_to_bin(bn, val)
#define _libssh2_bn_bytes(bn)
#define _libssh2_bn_bits(bn)
#define _libssh2_bn_free(bn)

const void *_libssh2_EVP_aes_128_ctr(void);
const void *_libssh2_EVP_aes_192_ctr(void);
const void *_libssh2_EVP_aes_256_ctr(void);
