/* Copyright (C) 2013-2014 Keith Duncan */

#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>
#import "CommonBigNum.h"

#define _libssh2_random(buf, len) SecRandomCopyBytes(kSecRandomDefault, len, buf)

// SHA1
#define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH

#define libssh2_sha1_ctx CC_SHA1_CTX
#define libssh2_sha1_init(ctx) CC_SHA1_Init(ctx)
#define libssh2_sha1_update(ctx, data, len) CC_SHA1_Update(&ctx, data, len)
#define libssh2_sha1_final(ctx, out) CC_SHA1_Final(out, &ctx)
#define libssh2_sha1(data, datalen, out) CC_SHA1(data, datalen, out)

// SHA256
#define SHA256_DIGEST_LENGTH CC_SHA256_DIGEST_LENGTH

#define libssh2_sha256_ctx CC_SHA256_CTX
#define libssh2_sha256_init(ctx) CC_SHA256_Init(ctx)
#define libssh2_sha256_update(ctx, data, len) CC_SHA256_Update(&ctx, data, len)
#define libssh2_sha256_final(ctx, out) CC_SHA256_Final(out, &ctx)
#define libssh2_sha256(data, datalen, out) CC_SHA256(data, datalen, out)

// MD5
#define LIBSSH2_MD5 1
#define MD5_DIGEST_LENGTH CC_MD5_DIGEST_LENGTH

#define libssh2_md5_ctx CC_MD5_CTX
#define libssh2_md5_init(ctx) CC_MD5_Init(ctx)
#define libssh2_md5_update(ctx, data, len) CC_MD5_Update(&ctx, data, len)
#define libssh2_md5_final(ctx, out) CC_MD5_Final(out, &ctx)
#define libssh2_md5(data, datalen, out) CC_MD5(data, datalen, out)

// HMAC
#define LIBSSH2_HMAC_RIPEMD 0

#define libssh2_hmac_ctx CCHmacContext
#define libssh2_hmac_ctx_init(ctx)
#define libssh2_hmac_sha1_init(ctx, key, keylen) CCHmacInit(ctx, kCCHmacAlgSHA1, key, keylen)
#define libssh2_hmac_md5_init(ctx, key, keylen) CCHmacInit(ctx, kCCHmacAlgMD5, key, keylen)
//#define libssh2_hmac_ripemd160_init(ctx, key, keylen)
#define libssh2_hmac_update(ctx, data, datalen) CCHmacUpdate(&ctx, data, datalen)
#define libssh2_hmac_final(ctx, data) CCHmacFinal(&ctx, data)
#define libssh2_hmac_cleanup(ctx)

#define libssh2_crypto_init()
#define libssh2_crypto_exit()

#define libssh2_prepare_iovec(vec, len)  /* Empty. */

#define _libssh2_cipher_ctx CCCryptorRef
extern void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx);

#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 0
#define LIBSSH2_BLOWFISH 1
#define LIBSSH2_RC4 1
#define LIBSSH2_CAST 1
#define LIBSSH2_3DES 1

typedef enum {
	_libssh2_cipher_aes256,
	_libssh2_cipher_aes256ctr,
	_libssh2_cipher_aes192,
	_libssh2_cipher_aes192ctr,
	_libssh2_cipher_aes128,
	_libssh2_cipher_aes128ctr,
	_libssh2_cipher_blowfish,
	_libssh2_cipher_arcfour,
	_libssh2_cipher_cast5,
	_libssh2_cipher_3des,
} _libssh2_securetransport_cipher;

#define _libssh2_cipher_type(name) _libssh2_securetransport_cipher name

/*******************************************************************/
/*
 * SecureTransport backend RSA functions
 */

#define LIBSSH2_RSA 1

typedef struct OpaqueSecKeyRef libssh2_rsa_ctx;
extern int _libssh2_rsa_free(libssh2_rsa_ctx *rsa);

/*******************************************************************/
/*
 * SecureTransport backend DSA functions
 */

#define LIBSSH2_DSA 1
typedef struct OpaqueSecKeyRef libssh2_dsa_ctx;
extern int _libssh2_dsa_free(libssh2_dsa_ctx *dsa);

/*******************************************************************/
/*
 * SecureTransport BigNum implementation
 */

typedef void *_libssh2_bn_ctx;
#define _libssh2_bn_ctx_new() NULL
#define _libssh2_bn_ctx_free(bnctx)

#define _libssh2_bn struct _CCBigNumRef
#define _libssh2_bn_init() CCCreateBigNum(NULL)
#define _libssh2_bn_init_from_bin() _libssh2_bn_init()

#define _libssh2_bn_rand(bn, bits, top, bottom) \
do {\
  if (bn != NULL) CCBigNumFree(bn);\
  bn = CCBigNumCreateRandom(NULL, bits, bits, 0);\
} while (0)

#define _libssh2_bn_mod_exp(r, a, power, modulus, ctx) CCBigNumModExp(r, a, power, modulus)

#define _libssh2_bn_set_word(bn, val) \
do {\
CCBigNumClear(bn);\
CCBigNumAddI(bn, bn, val);\
} while (0)

#define _libssh2_bn_from_bin(bn, len, val)\
do {\
	if (bn != NULL) CCBigNumFree(bn);\
	bn = CCBigNumFromData(NULL, val, len);\
} while(0)
#define _libssh2_bn_to_bin(bn, val) CCBigNumToData(NULL, bn, val)

#define _libssh2_bn_bytes(bn) CCBigNumByteCount(bn)
#define _libssh2_bn_bits(bn) CCBigNumBitCount(bn)

#define _libssh2_bn_free(bn) CCBigNumFree(bn)
