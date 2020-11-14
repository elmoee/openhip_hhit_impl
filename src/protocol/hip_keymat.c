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
 *  \file  hip_keymat.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Implements a HIP Keymat data structure for storing a
 *          shared secret key and it derivitives.
 *
 */
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/des.h> /* DES_KEY_SZ == 8 bytes*/
#include <openssl/dsa.h>
#include <openssl/kdf.h>
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#include <hip/hip_sadb.h>

#include "XKCP/SP800-185.h"

#define MAX_KEYS 8

/*
 * keys should be:
 * 0 initiator HIP key (24 bytes (3DES))
 * 1 responder HIP key (24 bytes (3DES))
 * 2 initiator ESP key (24 bytes (3DES))
 * 3 responder ESP key (24 bytes (3DES))
 * 4 initiator AUTH key (20 bytes (SHA))
 * 5 responder AUTH key (20 bytes (SHA))
 */

/*
 * This function takes a Diffie Hellman computed key as binary input and
 * stores it in the hip_a->keymat
 *
 */
int set_secret_key(unsigned char *key, hip_assoc *hip_a)
{

  if (NULL == key)
    {
      log_(NORM, "set_secret_key() passed in null key\n");
      return(-1);
    }

  if (hip_a->dh_secret)
    {
      free(hip_a->dh_secret);
    }
  hip_a->dh_secret = key;

#ifndef HIP_VPLS
  log_(NORM, "************\nDH secret key set to:\n0x");
  print_hex(hip_a->dh_secret, hip_a -> dh_secret_len);
  log_(NORM, "\n***********\n");
#endif

  return(hip_a -> dh_secret_len);
}

/*
 * get_key()
 *
 * IN:		hip_a = contains HITs and keymat
 *		type = type of key to get
 *		peer = TRUE if you want the peer's key, FALSE for keys that
 *			are associated with my HIT.
 * OUT:		Pointer to the proper key from the keymat.
 */
unsigned char *get_key(hip_assoc *hip_a, int type, int peer)
{
  int result, num = 0;

  result = compare_hits(hip_a->peer_hi->hit, hip_a->hi->hit);

  /* result > 0 means peer HIT larger than my HIT */
  switch (type)
    {
    case HIP_ENCRYPTION:
      peer ?  ((result > 0) ? (num = GL_HIP_ENCRYPTION_KEY) :
               (num = LG_HIP_ENCRYPTION_KEY)) :
      ((result > 0) ? (num = LG_HIP_ENCRYPTION_KEY) :
       (num = GL_HIP_ENCRYPTION_KEY));
      break;
    case HIP_INTEGRITY:
      peer ?  ((result > 0) ? (num = GL_HIP_INTEGRITY_KEY) :
               (num = LG_HIP_INTEGRITY_KEY)) :
      ((result > 0) ? (num = LG_HIP_INTEGRITY_KEY) :
       (num = GL_HIP_INTEGRITY_KEY));
      break;
    case ESP_ENCRYPTION:
      peer ?  ((result > 0) ? (num = GL_ESP_ENCRYPTION_KEY) :
               (num = LG_ESP_ENCRYPTION_KEY)) :
      ((result > 0) ? (num = LG_ESP_ENCRYPTION_KEY) :
       (num = GL_ESP_ENCRYPTION_KEY));
      break;
    case ESP_AUTH:
      peer ?  ((result > 0) ? (num = GL_ESP_AUTH_KEY) :
               (num = LG_ESP_AUTH_KEY)) :
      ((result > 0) ? (num = LG_ESP_AUTH_KEY) :
       (num = GL_ESP_AUTH_KEY));
      break;
    default:
      num = 0;
      break;
    }

  return(hip_a->keys[num].key);
}

/*
 * This function will derive and store only the required HIP keys
 * (ESP keys are computed later)
 */
void compute_keys(hip_assoc *hip_a)
{
  compute_keymat(hip_a);
  draw_keys(hip_a, TRUE, 0);
}

const EVP_MD* get_hkdf_md(hip_assoc *hip_a)
{
  //Uses RHASH from the HIT-suite to decide hash function
  switch (hip_a->hit_suite)
    {
    case HIT_SUITE_4BIT_RSA_DSA_SHA256:
      return EVP_sha256();
    case HIT_SUITE_4BIT_ECDSA_SHA384:
      return EVP_sha384();
    case HIT_SUITE_4BIT_ECDSA_LOW_SHA1:
      return EVP_sha1();
    default:
      // Default to SHA256 for backwards compatibility
      return EVP_sha256();
    }
}

/*
 * Compute a new keymat based on the DH secret Kij and HITs
 */

int compute_keymat(hip_assoc *hip_a)
{
  int result;
  int dh_secret_len, info_len, salt_len;
  size_t keymat_len;
  char *dh_secret, *info, *salt;
  BIGNUM *hit1, *hit2;
  hip_hit *hitp;

  if (hip_a == NULL)
    {
      log_(NORM, "no hip_a in compute_keymat()\n");
      return(-1);
    }
  hitp = &(hip_a->peer_hi->hit);
  if (hitp == NULL)
    {
      log_(NORM, "no peer HIT in compute_keymat()\n");
      return(-1);
    }

  hit1 = BN_bin2bn((unsigned char*)hitp, HIT_SIZE, NULL);
  hit2 = BN_bin2bn((unsigned char*)hip_a->hi->hit, HIT_SIZE, NULL);
  result = BN_ucmp(hit1, hit2);

  /* HKDF keying material */
  dh_secret_len = hip_a->dh_secret_len;
  info_len = 2 * HIT_SIZE;
  salt_len = 2 * sizeof(__u64);
  keymat_len = KEYMAT_SIZE;
  dh_secret = malloc(dh_secret_len);
  info = malloc(info_len);
  salt = malloc(salt_len);

  /* Kij */
  memcpy(dh_secret, hip_a->dh_secret, hip_a->dh_secret_len);

  /* sort(Resp-HIT, Init-HIT) */
  if (result <= 0)         /* hit1 <= hit2 */
    {
      memcpy(info, hitp, HIT_SIZE);
      memcpy(&info[HIT_SIZE],
             hip_a->hi->hit, HIT_SIZE);
    }
  else           /* hit1 > hit2 */
    {
      memcpy(info,
             hip_a->hi->hit, HIT_SIZE);
      memcpy(&info[HIT_SIZE], hitp, HIT_SIZE);
    }

  /* #I | #J */
  memcpy(salt, hip_a->cookie_r.i, sizeof(__u64));
  memcpy(&salt[sizeof(__u64)], hip_a->cookie_j, sizeof(__u64));

  // EDDSA/cSHAKE128 uses KKDF instead of HKDF
  switch (hip_a->hit_suite)
  {
  case HIT_SUITE_4BIT_EDDSA_CSHAKE128:
  {
    EVP_PKEY *initiatorPKEY = NULL;
    EVP_PKEY *responderPKEY = NULL;

    if (hip_a->role == ROLE_INITIATOR)
    {
      initiatorPKEY = hip_a->hi->eddsa;
      responderPKEY = hip_a->peer_hi->eddsa;
    }
    else if (hip_a->role == ROLE_RESPONDER)
    {
      initiatorPKEY = hip_a->peer_hi->eddsa;
      responderPKEY = hip_a->hi->eddsa;
    }
    else
    {
      log_(WARN, "Could not determine if this node is initiator or responder for KKDF\n");
      return -1;
    }


    size_t initiatorPubkeyLen = 0;
    EVP_PKEY_get_raw_public_key(initiatorPKEY, NULL, &initiatorPubkeyLen);
    unsigned char *initiatorPubKeyBuffer = malloc(initiatorPubkeyLen);
    if (initiatorPubKeyBuffer == NULL)
    {
      log_(WARN, "Failed to allocate memory for EdDSA public key\n");
      return -1;
    }
    EVP_PKEY_get_raw_public_key(initiatorPKEY, initiatorPubKeyBuffer, &initiatorPubkeyLen);

    size_t responderPubkeyLen = 0;
    EVP_PKEY_get_raw_public_key(responderPKEY, NULL, &responderPubkeyLen);
    unsigned char *responderPubKeyBuffer = malloc(responderPubkeyLen);
    if (responderPubKeyBuffer == NULL)
    {
      log_(WARN, "Failed to allocate memory for EdDSA public key\n");
      return -1;
    }
    EVP_PKEY_get_raw_public_key(responderPKEY, responderPubKeyBuffer, &responderPubkeyLen);

    unsigned char *kmacKey = malloc(info_len + salt_len);
    if (kmacKey == NULL)
    {
      log_(WARN, "Failed to allocate memory for KMAC key\n");
      return -1;
    }
    memcpy(kmacKey, salt, salt_len);
    memcpy(&kmacKey[salt_len], info, info_len);

    size_t ikmLen = hip_a->dh_secret_len + initiatorPubkeyLen + responderPubkeyLen;
    unsigned char *ikm = malloc(ikmLen);

    memcpy(ikm, dh_secret, dh_secret_len);
    memcpy(&ikm[dh_secret_len], initiatorPubKeyBuffer, initiatorPubkeyLen);
    memcpy(&ikm[dh_secret_len + initiatorPubkeyLen], responderPubKeyBuffer, responderPubkeyLen);

    int err = KMAC128(kmacKey, (salt_len + info_len) * 8, ikm, ikmLen * 8, hip_a->keymat, keymat_len * 8, (unsigned char *)"KDF", 8 * 3);

    free(initiatorPubKeyBuffer);
    free(responderPubKeyBuffer);
    free(kmacKey);
    free(ikm);

    if (err != 0)
    {
      log_(WARN, "Failed to derive keys using KMAC\n");
      return -1;
    }
  }
  break;
  case HIT_SUITE_4BIT_RSA_DSA_SHA256:
  case HIT_SUITE_4BIT_ECDSA_SHA384:
  case HIT_SUITE_4BIT_ECDSA_LOW_SHA1:
  {
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
      log_(ERR, "HKDF init failed\n");
      return -1;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, get_hkdf_md(hip_a)) <= 0)
    {
      log_(ERR, "HKDF message digest init failed\n");
      return -1;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0)
    {
      log_(ERR, "HKDF salt init failed\n");
      return -1;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, dh_secret, dh_secret_len) <= 0)
    {
      log_(ERR, "HKDF dh secret init failed\n");
      return -1;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0)
    {
      log_(ERR, "HKDF info init failed\n");
      return -1;
    }
    /* EXTRACT_AND_EXPAND is the default behaviour, 
        thus filling the keymat buffer with esp keys. */
    if (EVP_PKEY_derive(pctx, hip_a->keymat, &keymat_len) <= 0)
    {
      log_(ERR, "HKDF failed to derive keys\n");
      return -1;
    }
    break;
  default:
    log_(WARN, "Unsupported HIT suite in compute_keymat(): %d.\n",
         hip_a->hit_suite);
  }
  }

  free(info);
  free(salt); 
  free(dh_secret);
  BN_free(hit1);
  BN_free(hit2);
  return(0);
}

int draw_keys(hip_assoc *hip_a, int draw_hip_keys, int keymat_index)
{
  int location, i, k, max, key_type, len;

  if (hip_a == NULL)
    {
      log_(NORM, "no hip_a in draw_keys()\n");
      return(-1);
    }

  /* erase new key locations */
  if (draw_hip_keys)
    {
      i = 0;
      k = 0;
      max = GL_ESP_ENCRYPTION_KEY;
    }
  else
    {
      i = GL_ESP_ENCRYPTION_KEY;
      k = GL_ESP_ENCRYPTION_KEY;
      max = NUMKEYS;
    }
  for (; i < max; i++)
    {
      memset(hip_a->keys[i].key, 0, HIP_KEY_SIZE);
      hip_a->keys[i].length = 0;
      hip_a->keys[i].type = 0;
    }

  log_(NORM, "Using HIP transform of %d", hip_a->hip_cipher);
  if (draw_hip_keys)
    {
      log_(NORM, ".\nDrawing new HIP encryption/integrity keys:\n");
    }
  else
    {
      log_(NORM, " ESP transform of %d.\nDrawing new ESP keys from "
           "keymat index %d:\n", hip_a->esp_transform, keymat_index);
    }

  location = keymat_index;

  /* draw keys from the keymat */
  for (; k < max; k++)
    {
      /* decide what type/length of key to use */
      switch (k)
        {
        case GL_HIP_ENCRYPTION_KEY:             /* ENCRYPTED payload keys */
        case LG_HIP_ENCRYPTION_KEY:
          key_type = hip_a->hip_cipher;
          len = enc_key_len_hip_cipher(key_type);
          break;
        case GL_HIP_INTEGRITY_KEY:              /* HMAC keys */
        case LG_HIP_INTEGRITY_KEY:
          key_type = hip_a->hit_suite;
          len = auth_key_len_hit_suite(key_type);
          break;
        case GL_ESP_ENCRYPTION_KEY:             /* ESP encryption keys */
        case LG_ESP_ENCRYPTION_KEY:
          key_type = hip_a->esp_transform;
          len = enc_key_len(key_type);
          break;
        case GL_ESP_AUTH_KEY:           /* ESP authentication keys */
        case LG_ESP_AUTH_KEY:
          key_type = hip_a->esp_transform;
          len = auth_key_len(key_type);
          break;
        default:
          key_type = 0;               /* no key */
          len = 0;
          break;
        }
      /* load the key */
      hip_a->keys[k].type = key_type;
      hip_a->keys[k].length = len;
      memset(hip_a->keys[k].key, 0, HIP_KEY_SIZE);
      if ((location + len) > KEYMAT_SIZE)
        {
          log_(NORM, "No more keymat material for key %d!\n", k);
          return(-1);
        }

      log_(NORM, "Key %d (%d,%d) keymat[%3d] 0x",
           k, key_type, len, location);
      if (len)
        {
          memcpy(hip_a->keys[k].key,
                 &hip_a->keymat[location], len);
          location += len;
        }
      print_hex(hip_a->keys[k].key, len);
      log_(NORM, "\n");
    }

  hip_a->keymat_index = location;
  return(location);
}

int draw_mr_key(hip_assoc *hip_a, int keymat_index)
{
  int location, key_type, len;

  if (hip_a == NULL)
    {
      log_(NORM, "no hip_a in draw_mr_key()\n");
      return(-1);
    }

  location = keymat_index;
  key_type = hip_a->hip_transform;
  len = auth_key_len(key_type);
  hip_a->mr_key.type = key_type;
  hip_a->mr_key.length = len;
  if ((location + len) > KEYMAT_SIZE)
    {
      log_(NORM, "No more keymat material for mobile router key!\n");
      return(-1);
    }
  log_(NORM, "Mobile router key (%d,%d) keymat[%3d] 0x",
       key_type, len, location);
  if (len)
    {
      memcpy(hip_a->mr_key.key, &hip_a->keymat[location], len);
      location += len;
    }
  print_hex(hip_a->mr_key.key, len);
  log_(NORM, "\n");

  hip_a->keymat_index = location;
  return(location);
}

int auth_key_len_hit_suite(int suite_id)
{
  switch (suite_id)
  {
    case HIT_SUITE_4BIT_RSA_DSA_SHA256:
      return(KEY_LEN_SHA256);
    case HIT_SUITE_4BIT_ECDSA_SHA384:
      return(KEY_LEN_SHA384);
    case HIT_SUITE_4BIT_ECDSA_LOW_SHA1:
      return(KEY_LEN_SHA1);
    case HIT_SUITE_4BIT_EDDSA_CSHAKE128:
      return(KEY_LEN_CSHAKE128);
    default:
      return(KEY_LEN_SHA256);
  }
  return(0);
}

int auth_key_len(int suite_id)
{
  switch (suite_id)
    {
    case ESP_AES128_CBC_HMAC_SHA1:
      return(KEY_LEN_SHA1);
    case ESP_NULL_HMAC_SHA256:
    case ESP_AES128_CBC_HMAC_SHA256:
    case ESP_AES256_CBC_HMAC_SHA256:
      return(KEY_LEN_SHA256);
    default:
      break;
    }
  return(0);
}

int enc_key_len(int suite_id)
{
  switch (suite_id)
    {
    case ESP_AES128_CBC_HMAC_SHA1:
    case ESP_AES128_CBC_HMAC_SHA256:
      return(KEY_LEN_AES128);
    case ESP_AES256_CBC_HMAC_SHA256:
      return(KEY_LEN_AES256);
    case ESP_NULL_HMAC_SHA256:
      return(KEY_LEN_NULL);
    default:
      break;
    }
  return(0);
}

int enc_key_len_hip_cipher(int hip_cipher_id)
{
  switch (hip_cipher_id)
  {
    case HIP_CIPHER_AES128_CBC:
      return(KEY_LEN_AES128);
    case HIP_CIPHER_AES256_CBC:
      return(KEY_LEN_AES256);
    case HIP_CIPHER_NULL_ENCRYPT:
      return(KEY_LEN_NULL);
    case HIP_CIPHER_RIVER_KEYAK:
      return(KEY_LEN_RIVER_KEYAK);
    case HIP_CIPHER_LAKE_KEYAK:
      return(KEY_LEN_LAKE_KEYAK);
    default:
      break;
  }
  return(0);
}

int enc_iv_len(int hip_cipher_id)
{
  switch (hip_cipher_id)
    {
    case HIP_CIPHER_AES128_CBC:
    case HIP_CIPHER_AES256_CBC:
      return(16);               /* AES uses 128-bit IV */
    case HIP_CIPHER_NULL_ENCRYPT:
      return(0);
    case HIP_CIPHER_RIVER_KEYAK:
    case HIP_CIPHER_LAKE_KEYAK:
      return(16); // 128 bits TODO: Determine correct value for Keyak IV length
    break;
    default:
      break;
    }
  return(0);
}

int transform_to_ealg(int transform)
{
  switch (transform)
    {
    case ESP_AES128_CBC_HMAC_SHA1:                 /* AES-CBC enc */
    case ESP_AES128_CBC_HMAC_SHA256:
    case ESP_AES256_CBC_HMAC_SHA256:
      return(SADB_X_EALG_AESCBC);
    case ESP_NULL_HMAC_SHA256:                    /* NULL enc */
      return(SADB_EALG_NULL);
    default:
      return(0);
    }
}

int transform_to_aalg(int transform)
{
  switch (transform)
    {
    case ESP_AES128_CBC_HMAC_SHA1:                 /* HMAC-SHA1 auth */
      return(SADB_AALG_SHA1HMAC);
    case ESP_AES128_CBC_HMAC_SHA256:                 /* HMAC-SHA256 auth */
    case ESP_AES256_CBC_HMAC_SHA256:
    case ESP_NULL_HMAC_SHA256:
      return(SADB_X_AALG_SHA2_256HMAC);
    default:
      return(0);
    }
}
