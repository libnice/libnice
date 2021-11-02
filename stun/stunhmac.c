/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007-2009 Nokia Corporation. All rights reserved.
 *  Contact: Rémi Denis-Courmont
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Youness Alaoui, Collabora Ltd.
 *   Rémi Denis-Courmont, Nokia
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "rand.h"

#include "stunmessage.h"
#include "stunhmac.h"

#include <string.h>
#include <assert.h>

#if defined(USE_WIN32_CRYPTO)
#include <malloc.h>
typedef struct _StunKeyBlob {
  BLOBHEADER header;
  DWORD key_size;
  BYTE key_data[0];
} StunKeyBlob;
#elif defined(HAVE_OPENSSL)
#include <openssl/hmac.h>
#include <openssl/sha.h>
#else
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#endif

void stun_sha1 (const uint8_t *msg, size_t len, size_t msg_len, uint8_t *sha,
    const void *key, size_t keylen, int padding)
{
  uint16_t fakelen = htons (msg_len);
  uint8_t pad_char[64] = {0};

  assert (len >= 44u);

#if defined(USE_WIN32_CRYPTO)
{
  HCRYPTPROV prov;
  size_t blob_size;
  StunKeyBlob *blob;
  BLOBHEADER *header;
  HCRYPTKEY key_handle;
  HCRYPTHASH hash;
  HMAC_INFO info = {0};
  DWORD sha_digest_len;

#ifdef NDEBUG
#define TRY(x) x;
#else
  BOOL success;
#define TRY(x)                                  \
  success = x;                                  \
  assert (success);
#endif

  TRY (CryptAcquireContextW (&prov, NULL, NULL, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT));

  blob_size = sizeof (StunKeyBlob) + keylen;
  blob = _malloca (blob_size);
  header = &blob->header;
  header->bType = PLAINTEXTKEYBLOB;
  header->bVersion = CUR_BLOB_VERSION;
  header->reserved = 0;
  header->aiKeyAlg = CALG_RC2;
  blob->key_size = keylen;
  memcpy (blob->key_data, key, keylen);
  TRY (CryptImportKey (prov, (const BYTE *) blob, blob_size, 0,
        CRYPT_IPSEC_HMAC_KEY, &key_handle));
  _freea (blob);

  TRY (CryptCreateHash (prov, CALG_HMAC, key_handle, 0, &hash));

  info.HashAlgid = CALG_SHA1;
  TRY (CryptSetHashParam (hash, HP_HMAC_INFO, (const BYTE *) &info, 0));

  TRY (CryptHashData (hash, msg, 2, 0));
  TRY (CryptHashData (hash, (const BYTE *) &fakelen, 2, 0));
  TRY (CryptHashData (hash, msg + 4, len - 28, 0));

  /* RFC 3489 specifies that the message's size should be 64 bytes,
     and \x00 padding should be done */
  if (padding && ((len - 24) % 64) > 0) {
    uint16_t pad_size = 64 - ((len - 24) % 64);

    TRY (CryptHashData (hash, pad_char, pad_size, 0));
  }

  sha_digest_len = 20;
  TRY (CryptGetHashParam (hash, HP_HASHVAL, sha, &sha_digest_len, 0));

  TRY (CryptDestroyHash (hash));
  TRY (CryptDestroyKey (key_handle));
  TRY (CryptReleaseContext (prov, 0));
}
#elif defined(HAVE_OPENSSL)
{
#ifdef NDEBUG
#define TRY(x) x;
#else
  int ret;
#define TRY(x)                                  \
  ret = x;                                      \
  assert (ret == 1);
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
  HMAC_CTX stackctx;
  HMAC_CTX *ctx = &stackctx;
  HMAC_CTX_init (ctx);
#else
  HMAC_CTX *ctx = HMAC_CTX_new ();
#endif /* OPENSSL_VERSION_NUMBER */

  assert (SHA_DIGEST_LENGTH == 20);

  TRY (HMAC_Init_ex (ctx, key, keylen, EVP_sha1(), NULL));

  TRY (HMAC_Update (ctx, msg, 2));
  TRY (HMAC_Update (ctx, (unsigned char *)&fakelen, 2));
  TRY (HMAC_Update (ctx, msg + 4, len - 28));

  /* RFC 3489 specifies that the message's size should be 64 bytes,
     and \x00 padding should be done */
  if (padding && ((len - 24) % 64) > 0) {
    uint16_t pad_size = 64 - ((len - 24) % 64);

    TRY (HMAC_Update (ctx, pad_char, pad_size));
  }

  TRY (HMAC_Final (ctx, sha, NULL));

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
  HMAC_CTX_cleanup (ctx);
#else
  HMAC_CTX_free (ctx);
#endif /* OPENSSL_VERSION_NUMBER */
}
#else
{
  gnutls_hmac_hd_t handle;

#ifdef NDEBUG
#define TRY(x) x;
#else
  int ret;
#define TRY(x)                                  \
  ret = x;                                      \
  assert (ret >= 0);
#endif

  assert (gnutls_hmac_get_len (GNUTLS_MAC_SHA1) == 20);
  TRY (gnutls_hmac_init (&handle, GNUTLS_MAC_SHA1, key, keylen));

  TRY (gnutls_hmac (handle, msg, 2));
  TRY (gnutls_hmac (handle, &fakelen, 2));
  TRY (gnutls_hmac (handle, msg + 4, len - 28));

  /* RFC 3489 specifies that the message's size should be 64 bytes,
     and \x00 padding should be done */
  if (padding && ((len - 24) % 64) > 0) {
    uint16_t pad_size = 64 - ((len - 24) % 64);

    TRY (gnutls_hmac (handle, pad_char, pad_size));
  }

  gnutls_hmac_deinit (handle, sha);

#undef TRY
}
#endif /* HAVE_OPENSSL */
}

static const uint8_t *priv_trim_var (const uint8_t *var, size_t *var_len)
{
  const uint8_t *ptr = var;

  while (*ptr == '"') {
    ptr++;
    (*var_len)--;
  }
  while(ptr[*var_len-1] == '"' ||
      ptr[*var_len-1] == 0) {
    (*var_len)--;
  }

  return ptr;
}


void stun_hash_creds (const uint8_t *realm, size_t realm_len,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    unsigned char md5[16])
{
  const uint8_t *username_trimmed = priv_trim_var (username, &username_len);
  const uint8_t *password_trimmed = priv_trim_var (password, &password_len);
  const uint8_t *realm_trimmed = priv_trim_var (realm, &realm_len);
  const uint8_t *colon = (uint8_t *)":";

#if defined(USE_WIN32_CRYPTO)
  HCRYPTPROV prov;
  HCRYPTHASH hash;
  DWORD md5_digest_len;

  CryptAcquireContextW (&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  CryptCreateHash (prov, CALG_MD5, 0, 0, &hash);

  CryptHashData (hash, username_trimmed, username_len, 0);
  CryptHashData (hash, colon, 1, 0);
  CryptHashData (hash, realm_trimmed, realm_len, 0);
  CryptHashData (hash, colon, 1, 0);
  CryptHashData (hash, password_trimmed, password_len, 0);

  md5_digest_len = 16;
  CryptGetHashParam (hash, HP_HASHVAL, md5, &md5_digest_len, 0);

  CryptDestroyHash (hash);
  CryptReleaseContext (prov, 0);
#elif defined(HAVE_OPENSSL)
  EVP_MD_CTX *ctx;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
  ctx = EVP_MD_CTX_create ();
#else
  ctx = EVP_MD_CTX_new ();
#endif /* OPENSSL_VERSION_NUMBER */

  EVP_DigestInit_ex (ctx, EVP_md5(), NULL);
  EVP_DigestUpdate (ctx, username_trimmed, username_len);
  EVP_DigestUpdate (ctx, colon, 1);
  EVP_DigestUpdate (ctx, realm_trimmed, realm_len);
  EVP_DigestUpdate (ctx, colon, 1);
  EVP_DigestUpdate (ctx, password_trimmed, password_len);
  EVP_DigestFinal_ex (ctx, md5, NULL);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
  EVP_MD_CTX_destroy (ctx);
#else
  EVP_MD_CTX_free (ctx);
#endif /* OPENSSL_VERSION_NUMBER */

#else
  gnutls_hash_hd_t handle;

  gnutls_hash_init (&handle, GNUTLS_DIG_MD5);
  gnutls_hash (handle, username_trimmed, username_len);
  gnutls_hash (handle, colon, 1);
  gnutls_hash (handle, realm_trimmed, realm_len);
  gnutls_hash (handle, colon, 1);
  gnutls_hash (handle, password_trimmed, password_len);

  gnutls_hash_deinit (handle, md5);
#endif /* HAVE_OPENSSL */
}


void stun_make_transid (StunTransactionId id)
{
  nice_RAND_nonce (id, 16);
}
