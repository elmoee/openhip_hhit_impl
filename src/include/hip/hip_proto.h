/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2002-2012 the Boeing Company
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *  \file  hip_proto.h
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *		Tom Henderson, <thomas.r.henderson@boeing.com>
 *
 *  \brief  Definitions for the HIP protocol.
 *
 */

#ifndef _HIP_PROTO_H_
#define _HIP_PROTO_H_

#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>


/*
 * Protocol constants
 */


#define H_PROTO_UDP 17
#define HIP_UDP_PORT 10500

#define HIP_PROTO_VER 1
#define H_PROTO_HIP 139 /* IP layer protocol number for private encryption */
#define HIP_PAYLOAD_PROTOCOL 59
#define STATUS_PORT 4051 /* UDP port for obtaining status data */

#define SPI_RESERVED 255
#define HIP_ALIGN 4
#define ACCEPTABLE_R1_COUNT_RANGE 4

#define HIT_SIZE 16
#define HIT_PREFIX_TYPE1_SHA1   0x40

typedef enum {
  UNASSOCIATED,         /* State machine start			*/
  I1_SENT,              /* Initiating HIP			*/
  I2_SENT,              /* Waiting to finish HIP		*/
  R2_SENT,              /* Waiting to finish HIP		*/
  ESTABLISHED,          /* HIP SA established			*/
  REKEYING,             /* HIP SA established, rekeying		*/
  CLOSING,              /* HIP SA closing, no data can be sent	*/
  CLOSED,               /* HIP SA closed, no data can be sent	*/
  E_FAILED              /* HIP SA establishment failed		*/
} HIP_STATES;

typedef enum
{
  ROLE_INITIATOR,
  ROLE_RESPONDER
} HIP_ROLES;

/* HIP packet types */
typedef enum {
  HIP_I1 = 1,
  HIP_R1,
  HIP_I2,
  HIP_R2,
  CER,          /* 5 - removed from draft-ietf-hip-base-03 */
  BOS = 11,       /* 11 - removed from draft-ietf-hip-base-01 */
  UPDATE = 16,       /* 16 */
  NOTIFY = 17,       /* 17 */
  CLOSE = 18,        /* 18 */
  CLOSE_ACK = 19,       /* 19 */
  HIP_HDRR,       /* 20 */
} HIP_PACKETS;

/* HIP controls */
typedef enum {
  CTL_ANON        = 0x0001,
} HIP_CONTROLS;


/* HIP TLV parameters */
#define PARAM_ESP_INFO                  65
#define PARAM_R1_COUNTER                129
#define PARAM_LOCATOR                   193
#define PARAM_PUZZLE                    257
#define PARAM_SOLUTION                  321
#define PARAM_SEQ                       385
#define PARAM_ACK                       449
#define	PARAM_DH_GROUP_LIST	            511
#define PARAM_DIFFIE_HELLMAN            513
#define PARAM_HIP_CIPHER                579
#define PARAM_ENCRYPTED                 641
#define PARAM_HOST_ID                   705
#define PARAM_HIT_SUITE_LIST            715
#define PARAM_CERT                      768
#define PARAM_PROXY_TICKET              812
#define PARAM_AUTH_TICKET               822
#define PARAM_NOTIFY                    832
#define PARAM_ECHO_REQUEST              897
#define PARAM_REG_INFO                  930
#define PARAM_REG_REQUEST               932
#define PARAM_REG_RESPONSE              934
#define PARAM_REG_FAILED                936
#define PARAM_REG_REQUIRED              /* TBD */
#define PARAM_ECHO_RESPONSE             961
#define PARAM_ESP_TRANSFORM             4095
#define PARAM_TRANSFORM_LOW             2048 /* defines range for transforms */
#define PARAM_TRANSFORM_HIGH            4095
#define PARAM_HMAC                      61505
#define PARAM_HMAC_2                    61569
#define PARAM_HIP_SIGNATURE_2           61633
#define PARAM_HIP_SIGNATURE             61697
#define PARAM_ESP_INFO_NOSIG            62565
#define PARAM_ECHO_REQUEST_NOSIG        63661
#define PARAM_ECHO_RESPONSE_NOSIG       63425
#define PARAM_FROM                      65498
#define PARAM_RVS_HMAC                  65500
#define PARAM_VIA_RVS                   65502
#define PARAM_CRITICAL_BIT              0x0001

/* encryption algorithms */
typedef enum {
  RESERVED,                             /* 0 */
  ESP_AES128_CBC_HMAC_SHA1,             /* 1 */
  DEPRECATED_ESP_3DES_CBC_HMAC_SHA1,    /* 2 ( no longer supported, RFC7402 ) */
  DEPRECATED_ESP_3DES_CBC_HMAC_MD5,     /* 3 ( no longer supported, RFC7402 ) */
  DEPRECATED_ESP_BLOWFISH_CBC_HMAC_SHA1,/* 4 ( no longer supported, RFC7402 ) */
  DEPRECATED_ESP_NULL_HMAC_SHA1,        /* 5 ( no longer supported, RFC7402 ) */
  DEPRECATED_ESP_NULL_HMAC_MD5,         /* 6 ( no longer supported, RFC7402 ) */
  ESP_NULL_HMAC_SHA256,                 /* 7 */
  ESP_AES128_CBC_HMAC_SHA256,           /* 8 */
  ESP_AES256_CBC_HMAC_SHA256,           /* 9 */
  ESP_AES_CCM_8,                        /* 10 ( not fully implmented yet ) */
  ESP_AES_CCM_16,                       /* 11 ( not fully implmented yet ) */
  ESP_AES_GCM_ICV_8,                    /* 12 ( not fully implmented yet ) */
  ESP_AES_GCM_ICV_16,                   /* 13 ( not fully implmented yet ) */
  ESP_AES_CMAC_96,                      /* 14 ( not fully implmented yet ) */
  ESP_AES_GMAC,                         /* 15 ( not fully implmented yet ) */
  ESP_MAX,                         /* 16 */
} SUITE_IDS;

typedef enum {
  HIP_CIPHER_RESERVED,                  /* 0 */
  HIP_CIPHER_NULL_ENCRYPT,              /* 1 */
  HIP_CIPHER_AES128_CBC,                /* 2 */
  HIP_CIPHER_RESERVED_2,                /* 3 */
  HIP_CIPHER_AES256_CBC,                /* 4 */
  HIP_CIPHER_RESERVED_3,                /* 5 */
  HIP_CIPHER_RIVER_KEYAK,               /* 6 */
  HIP_CIPHER_LAKE_KEYAK,                /* 7 */
  HIP_CIPHER_MAX,                       /* 8 */
} CIPHER_IDS;

/* HIT suites (8 bit encoding) */
typedef enum {
  HIT_SUITE_8BIT_RESERVED = 0x00,
  HIT_SUITE_8BIT_RSA_DSA_SHA256 = 0x10,
  HIT_SUITE_8BIT_ECDSA_SHA384 = 0x20,
  HIT_SUITE_8BIT_ECDSA_LOW_SHA1 = 0x30,
  HIT_SUITE_8BIT_EDDSA_CSHAKE128 = 0x50,
} HIT_SUITES_8BIT;

/* HIT suites (4 bit encoding) */
typedef enum {
  HIT_SUITE_4BIT_RESERVED,
  HIT_SUITE_4BIT_RSA_DSA_SHA256,
  HIT_SUITE_4BIT_ECDSA_SHA384,
  HIT_SUITE_4BIT_ECDSA_LOW_SHA1,
  HIT_SUITE_4BIT_RESERVED_2,
  HIT_SUITE_4BIT_EDDSA_CSHAKE128,
  HIT_SUITE_4BIT_MAX,
} HIT_SUITES_4BIT;

#define ENCR_NULL(a) (a == HIP_CIPHER_NULL_ENCRYPT)
/* Supported transforms are compressed into a bitmask... */
/* Default HIP transforms proposed when none are specified in config */
#define DEFAULT_HIP_TRANS \
  ((1 << ESP_AES128_CBC_HMAC_SHA1) | \
   (1 << ESP_NULL_HMAC_SHA256) | \
   (1 << ESP_AES128_CBC_HMAC_SHA256) | \
   (1 << ESP_AES256_CBC_HMAC_SHA256) | \
   (1 << ESP_AES_CCM_8) | \
   (1 << ESP_AES_CCM_16) | \
   (1 << ESP_AES_GCM_ICV_8) | \
   (1 << ESP_AES_GCM_ICV_16) | \
   (1 << ESP_AES_CMAC_96) | \
   (1 << ESP_AES_GMAC))
/* Default ESP transforms proposed when none are specified in config */
#define ESP_OFFSET 8
#define DEFAULT_ESP_TRANS \
  ((1 << (ESP_OFFSET + ESP_AES128_CBC_HMAC_SHA1)) | \
   (1 << (ESP_OFFSET + ESP_NULL_HMAC_SHA256)) | \
   (1 << (ESP_OFFSET + ESP_AES128_CBC_HMAC_SHA256)) | \
   (1 << (ESP_OFFSET + ESP_AES256_CBC_HMAC_SHA256)) | \
   (1 << (ESP_OFFSET + ESP_AES_CCM_8)) | \
   (1 << (ESP_OFFSET + ESP_AES_CCM_16)) | \
   (1 << (ESP_OFFSET + ESP_AES_GCM_ICV_8)) | \
   (1 << (ESP_OFFSET + ESP_AES_GCM_ICV_16)) | \
   (1 << (ESP_OFFSET + ESP_AES_CMAC_96)) | \
   (1 << (ESP_OFFSET + ESP_AES_GMAC)))

/* HI (signature) algorithms  */
typedef enum {
  HI_ALG_RESERVED,
  HI_ALG_DSA = 3,
  HI_ALG_RSA = 5,
  HI_ALG_ECDSA = 7,
  HI_ALG_ECDSA_LOW = 9,
  HI_ALG_EDDSA = 13,
} HI_ALGORITHMS;
#define HIP_RSA_DFT_EXP RSA_F4 /* 0x10001L = 65537; 3 and 17 are also common */
#define HI_TYPESTR(a)  ((a == HI_ALG_DSA) ? "DSA" : \
                        (a == HI_ALG_RSA) ? "RSA" : \
                        (a == HI_ALG_ECDSA) ? "ECDSA" : \
                        (a == HI_ALG_ECDSA_LOW) ? "ECDSA_LOW" : \
                        (a == HI_ALG_EDDSA) ? "EdDSA" : "UNKNOWN")

/* SADB algorithms */
#define SADB_EALG_3DESCBC         3
#define SADB_AALG_MD5HMAC         2
#define SADB_AALG_SHA1HMAC        3
#define SADB_X_AALG_SHA2_256HMAC  5
#define SADB_X_EALG_BLOWFISHCBC   7
#define SADB_EALG_NULL            11
#define SADB_X_EALG_AESCBC        12

/* HI Domain Identifier types */
typedef enum {
  DIT_NONE,             /* none included */
  DIT_FQDN,             /* Fully Qualified Domain Name, in binary format */
  DIT_NAI,              /* Network Access Identifier, binary, login@FQDN */
} HI_DIT;

typedef enum {
  UNVERIFIED,
  ACTIVE,
  DEPRECATED,
  DELETED,              /* not in spec, but used when address is removed */
} ADDRESS_STATES;

typedef enum {
  HIP_ENCRYPTION,
  HIP_INTEGRITY,
  ESP_ENCRYPTION,
  ESP_AUTH,
} KEY_TYPES;

typedef enum {
  GL_HIP_ENCRYPTION_KEY,        /* 0 */
  GL_HIP_INTEGRITY_KEY,
  LG_HIP_ENCRYPTION_KEY,
  LG_HIP_INTEGRITY_KEY,
  GL_ESP_ENCRYPTION_KEY,
  GL_ESP_AUTH_KEY,
  LG_ESP_ENCRYPTION_KEY,
  LG_ESP_AUTH_KEY       /* 7 */
} HIP_KEYMAT_KEYS;

typedef enum {
  KEY_LEN_NULL = 0,             /* RFC 2410 */
  KEY_LEN_MD5 = 16,             /* 128 bits per RFC 2403 */
  KEY_LEN_SHA1 = 20,            /* 160 bits per RFC 2404 */
  KEY_LEN_SHA256 = 32,
  KEY_LEN_SHA384 = 48,
  KEY_LEN_CSHAKE128 = 32,       /* 256 bits per Internet-Draft draft-moskowitz-hip-new-crypto-05 */
  KEY_LEN_3DES = 24,            /* 192 bits (3x64-bit keys) RFC 2451 */
  KEY_LEN_AES128 = 16,          /* 128 bits per RFC 3686; also 192, 256-bits */
  KEY_LEN_AES256 = 32,          /* 256 bits */
  KEY_LEN_BLOWFISH = 16,        /* 128 bits per RFC 2451 */
  KEY_LEN_RIVER_KEYAK = 32,     /* 256 bits TODO: Determine proper values for Keyak key length */
  KEY_LEN_LAKE_KEYAK = 32,      /* 256 bits TODO: Determine proper values for Keyak key length */
} HIP_KEYLENS;

/* Diffie-Hellman Group IDs */
typedef enum {
  DH_RESERVED,
  DH_DEPRICATED1,
  DH_DEPRECATED2,
  DH_MODP_1536,
  DH_MODP_3072,
  DH_DEPRECATED3,
  DH_DEPRECATED4,
  DH_NIST_256,
  DH_NIST_384,
  DH_NIST_521,
  DH_SECP160R1,
  DH_MODP_2048,
  DH_RESERVED_2,
  DH_CURVE_25519,
  DH_CURVE_448,
  DH_MAX
} DH_GROUP_IDS;

/* ECDSA curve IDs*/
typedef enum {
  ECDSA_RESERVED,
  ECDSA_256,
  ECDSA_384,
  ECDSA_MAX
} ECDSA_CURVE_IDS;

/* EDDSA curve IDs*/
typedef enum {
  EDDSA_RESERVED,
  EDDSA_25519,
  EDDSA_25519PH,
  EDDSA_448,
  EDDSA_448PH,
  EDDSA_MAX
} EDDSA_CURVE_IDS;

/* choose default DH group here */
#define DEFAULT_DH_GROUP_ID  DH_MODP_1536

//extern const __u8 DEFAULT_DH_GROUP_LIST[] = {DH_MODP_1536, DH_MODP_3072};
#define DH_MAX_LEN 1024
/*
 * HIP LOCATOR parameters
 */
#define LOCATOR_PREFERRED               0x01
#define LOCATOR_TRAFFIC_TYPE_BOTH       0x00
#define LOCATOR_TRAFFIC_TYPE_SIGNALING  0x01
#define LOCATOR_TRAFFIC_TYPE_DATA       0x02
#define LOCATOR_TYPE_IPV6               0x00
#define LOCATOR_TYPE_SPI_IPV6           0x01

/*
 * Notify error types
 */
#define NOTIFY_UNSUPPORTED_CRITICAL_PARAMETER_TYPE        1
#define NOTIFY_INVALID_SYNTAX                             7
#define NOTIFY_NO_DH_PROPOSAL_CHOSEN                     14
#define NOTIFY_INVALID_DH_CHOSEN                         15
#define NOTIFY_NO_HIP_PROPOSAL_CHOSEN                    16
#define NOTIFY_INVALID_HIP_CIPHER_CHOSEN                 17
#define NOTIFY_NO_ESP_PROPOSAL_CHOSEN                    18
#define NOTIFY_INVALID_ESP_TRANSFORM_CHOSEN              19
#define NOTIFY_UNSUPPORTED_HIT_SUITE                     20
#define NOTIFY_AUTHENTICATION_FAILED                     24
#define NOTIFY_CHECKSUM_FAILED                           26
#define NOTIFY_HMAC_FAILED                               28
#define NOTIFY_ENCRYPTION_FAILED                         32
#define NOTIFY_INVALID_HIT                               40
#define NOTIFY_BLOCKED_BY_POLICY                         42
#define NOTIFY_SERVER_BUSY_PLEASE_RETRY                  44
#define NOTIFY_LOCATOR_TYPE_UNSUPPORTED                  46
#define NOTIFY_I2_ACKNOWLEDGEMENT                        16384
#define NOTIFY_LOSS_DETECT                               16385

/*
 * Registration types
 */
typedef enum {
  REGTYPE_RESERVED,
  REGTYPE_RVS,                  /* 1 = Rendezvous Server */
  REGTYPE_RELAY_UDP_HIP,        /* 2 = UDP/HIP NAT Relay Server */
  REGTYPE_MR,                   /* 3 = Mobile Router */
} HIP_REGTYPES;

#endif /* !_HIP_PROTO_H_ */


