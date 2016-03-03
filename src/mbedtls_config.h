/** @file polarssl-config.h
  * polarssl configuration
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.08
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef __MBEDTLS_CONFIG_H__
#define __MBEDTLS_CONFIG_H__
///////////////////////////////////////////////////////////////////////////////

// base
#define MBEDTLS_BASE64_C

// hash
#define MBEDTLS_MD4_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C

// cipher
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS

#define MBEDTLS_HAVE_ASM
#define MBEDTLS_CIPHER_C
#define MBEDTLS_DES_C
#define MBEDTLS_PADLOCK_C
#define MBEDTLS_BLOWFISH_C
#define MBEDTLS_AES_C
#define MBEDTLS_AESNI_C

// random number generator and entropy
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

// PKI cryptography
#define MBEDTLS_PK_C
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_FS_IO
#define MBEDTLS_OID_C
#define MBEDTLS_PLATFORM_SNPRINTF_ALT

#include "mbedtls/check_config.h"
///////////////////////////////////////////////////////////////////////////////
#endif // __MBEDTLS_CONFIG_H__
