/* Copyright (C) 2013-2014 Keith Duncan */

#import "securetransport.h"

#include "libssh2_priv.h"
#include <Security/SecAsn1Coder.h>

#pragma mark Utilities

static CFDataRef CreateDataFromFile(char const *path) {
  CFStringRef keyFilePath = CFStringCreateWithCString(kCFAllocatorDefault, path, kCFStringEncodingUTF8);
  CFURLRef keyFileLocation = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, keyFilePath, kCFURLPOSIXPathStyle, false);
  CFRelease(keyFilePath);

  CFReadStreamRef readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault, keyFileLocation);
  CFRelease(keyFileLocation);

  if (!CFReadStreamOpen(readStream)) {
    CFRelease(readStream);
    return NULL;
  }

  CFMutableDataRef keyData = CFDataCreateMutable(kCFAllocatorDefault, 0);

  size_t size = 1024;
  uint8_t bytes[size];

  while (1) {
    CFIndex read = CFReadStreamRead(readStream, bytes, size);
    if (read == 0) {
      break;
    }
    else if (read < 0) {
      CFRelease(keyData);
      keyData = NULL;
      break;
    }

    CFDataAppendBytes(keyData, bytes, read);
  }

  CFReadStreamClose(readStream);
  CFRelease(readStream);

  return (CFDataRef)keyData;
}

#pragma mark - PKCS#1

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// <http://tools.ietf.org/html/rfc3447#appendix-A.1.2>

typedef struct {
  CSSM_DATA version; // RSA_Version_TwoPrime
  CSSM_DATA modulus;
  CSSM_DATA publicExponent;
  CSSM_DATA privateExponent;
  CSSM_DATA prime1;
  CSSM_DATA prime2;
  CSSM_DATA exponent1;
  CSSM_DATA exponent2;
  CSSM_DATA coefficient;
} _libssh2_pkcs1_rsa_private_key;

typedef enum {
  RSA_Version_TwoPrime = 0,
  RSA_Version_Multi = 1,
} RSA_Version;

static SecAsn1Template const _libssh2_pkcs1_rsa_private_key_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_pkcs1_rsa_private_key) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, version) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, modulus) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, publicExponent) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, privateExponent) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, prime1) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, prime2) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, exponent1) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, exponent2) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_private_key, coefficient) },
  { },
};

typedef struct {
  CSSM_DATA modulus;
  CSSM_DATA publicExponent;
} _libssh2_pkcs1_rsa_public_key;

static SecAsn1Template const _libssh2_pkcs1_rsa_public_key_template[] = {
  { .kind = SEC_ASN1_SEQUENCE, .size = sizeof(_libssh2_pkcs1_rsa_public_key) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_public_key, modulus) },
  { .kind = SEC_ASN1_INTEGER, .offset = offsetof(_libssh2_pkcs1_rsa_public_key, publicExponent) },
  { },
};

#pragma clang diagnostic pop

#pragma mark - RSA

int _libssh2_rsa_free(libssh2_rsa_ctx *rsa) {
  CFRelease(rsa);
  return 0;
}

static int _libssh2_rsa_new_from_data(libssh2_rsa_ctx **rsa, CFDataRef keyData, SecExternalItemType type, char const *filename, char const *passphrase) {
  CFURLRef cfLocation = NULL;
  if (filename != NULL) {
    cfLocation = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (UInt8 const *)filename, strlen(filename), false);
  }

  CFStringRef cfPassphrase = NULL;
  if (passphrase != NULL) {
    cfPassphrase = CFStringCreateWithBytes(kCFAllocatorDefault, (UInt8 const *)passphrase, strlen((const char *)passphrase), kCFStringEncodingASCII, false);
  }

  CFArrayRef attributes = CFArrayCreate(kCFAllocatorDefault, (void const **)&kSecAttrIsExtractable, 1, &kCFTypeArrayCallBacks);

  SecExternalFormat format = kSecFormatUnknown;
  SecExternalItemType typeRef = type;
  SecItemImportExportKeyParameters parameters = {
    .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
    .passphrase = cfPassphrase,
    .keyAttributes = attributes,
  };
  CFArrayRef items = NULL;

  do {
    if (cfLocation == NULL) {
      break;
    }
    if (cfPassphrase != NULL) {
      break;
    }

    CFStringRef pathExtension = CFURLCopyPathExtension(cfLocation);
    if (pathExtension == NULL) {
      break;
    }

    // Non-encrypted PKCS#8 keys are not supported by `impExpPkcs8Import`
    //
    // To fake support for it, we have to wrap the binary key in a PEM container
    // and then import it ¬_¬
    CFRange p8Range = CFStringFind(pathExtension, CFSTR("p8"), kCFCompareCaseInsensitive);
    CFRelease(pathExtension);

    if (p8Range.location != 0) {
      break;
    }

    SecTransformRef encodeTransform = SecEncodeTransformCreate(kSecBase64Encoding, NULL);
    if (encodeTransform == NULL) {
      break;
    }
    Boolean setInput = SecTransformSetAttribute(encodeTransform, kSecTransformInputAttributeName, keyData, NULL);
    if (!setInput) {
      CFRelease(encodeTransform);
    }

    CFDataRef encodedKeyData = SecTransformExecute(encodeTransform, NULL);
    CFRelease(encodeTransform);

    if (encodedKeyData == NULL) {
      break;
    }

    CFMutableDataRef pemData = CFDataCreateMutable(kCFAllocatorDefault, 0);
    char const *pemPrefix = "-----BEGIN PRIVATE KEY-----\n";
    CFDataAppendBytes(pemData, (const uint8_t *)pemPrefix, strlen(pemPrefix));
    CFDataAppendBytes(pemData, CFDataGetBytePtr(encodedKeyData), CFDataGetLength(encodedKeyData));
    char const *pemSuffix = "\n-----END PRIVATE KEY-----";
    CFDataAppendBytes(pemData, (const uint8_t *)pemSuffix, strlen(pemSuffix));

    CFRelease(encodedKeyData);

    keyData = pemData;

    CFURLRef newLocation = CFURLCreateCopyDeletingPathExtension(kCFAllocatorDefault, cfLocation);
    CFRelease(cfLocation);
    cfLocation = CFURLCreateCopyAppendingPathExtension(kCFAllocatorDefault, newLocation, CFSTR("pem"));
    CFRelease(newLocation);
  } while (0);

  CFStringRef cfPath = (cfLocation ? CFURLGetString(cfLocation) : NULL);

  OSStatus error = SecItemImport(keyData, cfPath, &format, &typeRef, 0, &parameters, NULL, &items);

  CFRelease(attributes);

  if (cfLocation != NULL) {
    CFRelease(cfLocation);
  }

  if (cfPassphrase != NULL) {
    CFRelease(cfPassphrase);
  }

  if (error != errSecSuccess) {
    return 1;
  }

  if (CFArrayGetCount(items) > 1) {
    CFRelease(items);
    return 1;
  }

  CFTypeRef item = CFArrayGetValueAtIndex(items, 0);
  if (CFGetTypeID(item) != SecKeyGetTypeID()) {
    CFRelease(items);
    return 1;
  }

  *rsa = (SecKeyRef)CFRetain(item);

  CFRelease(items);

  return 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static int _libssh2_rsa_new_from_binary_template(libssh2_rsa_ctx **rsa,
                                                 CSSM_KEYBLOB_FORMAT format,
                                                 CSSM_KEYCLASS keyClass,
                                                 void const *bytes,
                                                 SecAsn1Template const *templates) {
  SecExternalItemType type;
  switch (keyClass) {
    case CSSM_KEYCLASS_PRIVATE_KEY:
      type = kSecItemTypePrivateKey;
      break;
    case CSSM_KEYCLASS_PUBLIC_KEY:
      type = kSecItemTypePublicKey;
      break;
    default:
      return 1;
  }

  SecAsn1CoderRef coder = NULL;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != noErr) {
    return 1;
  }

  CSSM_DATA keyData = {};
  error = SecAsn1EncodeItem(coder, bytes, templates, &keyData);
  if (error != noErr) {
    SecAsn1CoderRelease(coder);
    return 1;
  }

  CFDataRef cfKeyData = CFDataCreate(kCFAllocatorDefault, keyData.Data, keyData.Length);

  SecAsn1CoderRelease(coder);

  int keyError = _libssh2_rsa_new_from_data(rsa, cfKeyData, type, NULL, NULL);

  CFRelease(cfKeyData);

  return keyError;
}

#pragma clang diagnostic pop

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

  uint8_t version = RSA_Version_TwoPrime;

  _libssh2_pkcs1_rsa_private_key keyData = {
    .version = {
      .Length = sizeof(version),
      .Data = &version,
    },
    .modulus = {
      .Length = nlen,
      .Data = (uint8_t *)ndata,
    },
    .publicExponent = {
      .Length = elen,
      .Data = (uint8_t *)edata,
    },
    .privateExponent = {
      .Length = dlen,
      .Data = (uint8_t *)ddata,
    },
    .prime1 = {
      .Length = plen,
      .Data = (uint8_t *)pdata,
    },
    .prime2 = {
      .Length = qlen,
      .Data = (uint8_t *)qdata,
    },
    .exponent1 = {
      .Length = e1len,
      .Data = (uint8_t *)e1data,
    },
    .exponent2 = {
      .Length = e2len,
      .Data = (uint8_t *)e2data,
    },
    .coefficient = {
      .Length = coefflen,
      .Data = (uint8_t *)coeffdata,
    },
  };
  return _libssh2_rsa_new_from_binary_template(rsa, CSSM_KEYBLOB_RAW_FORMAT_PKCS1, CSSM_KEYCLASS_PRIVATE_KEY, &keyData, _libssh2_pkcs1_rsa_private_key_template);
}

/*
    Create an RSA private key from a file.

    Supported formats:
 
        Format  | Encrypted | Non-encrypted |
    
    PKCS#1 PEM        x             x
    PKCS#8 DER        x             x
    PKCS#8 PEM        x             x
 
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

  CFDataRef keyData = CreateDataFromFile(filename);
  if (keyData == NULL) {
    return 1;
  }

  int error = _libssh2_rsa_new_from_data(rsa, keyData, kSecItemTypePrivateKey, filename, (char const *)passphrase);

  CFRelease(keyData);

  return error;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static SecKeyRef convert_rsa_private_key(CSSM_KEY const *keyRef) {
  if (keyRef->KeyHeader.AlgorithmId != CSSM_ALGID_RSA) return NULL;
  if (keyRef->KeyHeader.Format != CSSM_KEYBLOB_RAW_FORMAT_PKCS1) return NULL;
  if (keyRef->KeyHeader.KeyClass != CSSM_KEYCLASS_PRIVATE_KEY) return NULL;

  SecAsn1CoderRef coder;
  OSStatus error = SecAsn1CoderCreate(&coder);
  if (error != errSecSuccess) {
    return NULL;
  }

  _libssh2_pkcs1_rsa_private_key privateKeyData = {};
  error = SecAsn1Decode(coder, keyRef->KeyData.Data, keyRef->KeyData.Length, _libssh2_pkcs1_rsa_private_key_template, &privateKeyData);
  if (error != errSecSuccess) {
    SecAsn1CoderRelease(coder);
    return NULL;
  }

  _libssh2_pkcs1_rsa_public_key publicKeyData = {
    .modulus = privateKeyData.modulus,
    .publicExponent = privateKeyData.publicExponent,
  };

  SecKeyRef publicKey;
  int keyError = _libssh2_rsa_new_from_binary_template(&publicKey, CSSM_KEYBLOB_RAW_FORMAT_PKCS1, CSSM_KEYCLASS_PUBLIC_KEY, &publicKeyData, _libssh2_pkcs1_rsa_public_key_template);

  SecAsn1CoderRelease(coder);

  if (keyError != 0) {
    return NULL;
  }

  return publicKey;
}

static SecKeyRef convert_rsa_private_key_to_public_key(SecKeyRef privateKey) {
  CSSM_KEY const *keyRef;
  OSStatus error = SecKeyGetCSSMKey(privateKey, &keyRef);
  if (error != errSecSuccess) {
    return NULL;
  }

  if (keyRef->KeyHeader.BlobType == CSSM_KEYBLOB_REFERENCE) {
    CSSM_CSP_HANDLE csp;
    error = SecKeyGetCSPHandle(privateKey, &csp);
    if (error != errSecSuccess) {
      return NULL;
    }

    CSSM_KEY rawKey = {};
    CSSM_ACCESS_CREDENTIALS credentials = {};

    CSSM_CC_HANDLE context;
    CSSM_RETURN cssmError = CSSM_CSP_CreateSymmetricContext(csp, CSSM_ALGID_NONE, CSSM_ALGMODE_NONE, &credentials, NULL, NULL, CSSM_PADDING_NONE, 0, &context);
    if (cssmError != CSSM_OK) {
      return NULL;
    }

    CSSM_CONTEXT_ATTRIBUTE wrapFormat = {
      .AttributeType = CSSM_ATTRIBUTE_PRIVATE_KEY_FORMAT,
      .AttributeLength = sizeof(uint32),
      .Attribute.Uint32 = CSSM_KEYBLOB_RAW_FORMAT_PKCS1,
    };
    cssmError = CSSM_UpdateContextAttributes(context, 1, &wrapFormat);
    if (cssmError != CSSM_OK) {
      CSSM_DeleteContext(context);
      return NULL;
    }

    cssmError = CSSM_WrapKey(context, &credentials, keyRef, NULL, &rawKey);
    if (cssmError != CSSM_OK) {
      CSSM_DeleteContext(context);
      return NULL;
    }

    SecKeyRef publicKey = convert_rsa_private_key(&rawKey);

    CSSM_DeleteContext(context);

    return publicKey;
  }

  return convert_rsa_private_key(keyRef);
}

#pragma clang diagnostic pop

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

  SecKeyRef publicKey = convert_rsa_private_key_to_public_key(rsa);
  if (publicKey == NULL) {
    return 1;
  }

  CFDataRef signatureData = CFDataCreate(kCFAllocatorDefault, sig, sig_len);

  SecTransformRef transform = SecVerifyTransformCreate(publicKey, signatureData, NULL);

  CFRelease(publicKey);

  if (transform == NULL) {
    CFRelease(signatureData);
  }

  Boolean setAttributes = true;
  setAttributes &= SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsDigest, NULL);

  CFDataRef message = CFDataCreate(kCFAllocatorDefault, m, m_len);
  setAttributes &= SecTransformSetAttribute(transform, kSecTransformInputAttributeName, message, NULL);

  if (!setAttributes) {
    CFRelease(message);
    CFRelease(transform);
    CFRelease(signatureData);
    return 1;
  }

  CFErrorRef error = NULL;
  CFTypeRef output = SecTransformExecute(transform, &error);

  CFRelease(message);
  CFRelease(transform);
  CFRelease(signatureData);

  if (output == NULL) {
    CFRelease(error);
    return 1;
  }

  return (output == kCFBooleanTrue ? 0 : 1);
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
  assert(rsa != NULL);
  assert(hash != NULL);
  assert(signature != NULL);
  assert(signature_len != NULL);

  SecTransformRef transform = SecSignTransformCreate(rsa, NULL);
  if (transform == NULL) {
    return 1;
  }

  Boolean setAttributes = true;
  setAttributes &= SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsDigest, NULL);

  CFDataRef inputData = CFDataCreate(kCFAllocatorDefault, hash, hash_len);
  setAttributes &= SecTransformSetAttribute(transform, kSecTransformInputAttributeName, inputData, NULL);

  if (!setAttributes) {
    CFRelease(inputData);
    CFRelease(transform);
    return 1;
  }

  CFDataRef signatureData = SecTransformExecute(transform, NULL);

  CFRelease(inputData);
  CFRelease(transform);

  if (signatureData == NULL) {
    return 1;
  }

  *signature_len = CFDataGetLength(signatureData);
  *signature = session ? LIBSSH2_ALLOC(session, *signature_len) : malloc(*signature_len);

  CFDataGetBytes(signatureData, CFRangeMake(0, *signature_len), *signature);
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
 
    `sig` must be of length `SHA_DIGEST_LENGTH`.
 
    Returns 0 if the signature is valid, 1 otherwise.
 */
int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx * dsa,
                             const unsigned char *sig,
                             const unsigned char *m,
                             unsigned long m_len) {
  assert(dsa != NULL);
  assert(sig != NULL);
  assert(m != NULL);
  return 0;
}

/*
    Sign a SHA1 hash with a DSA key.

    dsa           - Initialised DSA key, non NULL.
    hash          - In parameter, SHA1 hash bytes.
    hash_len      - In parameter, length of hash.
    signature     - In parameter, pre malloced size of `SHA_DIGEST_LENGTH`.
 
    Returns 0 if the signature has been populated, 1 otherwise.
 */
int _libssh2_dsa_sha1_sign(libssh2_dsa_ctx * dsa,
                           const unsigned char *hash,
                           unsigned long hash_len,
                           unsigned char *sig) {
  assert(dsa != NULL);
  assert(hash != NULL);
  assert(sig != NULL);
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
