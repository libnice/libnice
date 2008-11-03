/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
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

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "stunmessage.h"
#include "stunhmac.h"

#include <string.h>
#include <assert.h>

void stun_sha1 (const uint8_t *msg, size_t len, uint8_t *sha,
    const void *key, size_t keylen, int padding)
{
  HMAC_CTX ctx;
  uint16_t fakelen = htons (len - 20u);

  assert (len >= 44u);

  HMAC_CTX_init (&ctx);
  HMAC_Init_ex (&ctx, key, keylen, EVP_sha1 (), NULL);
  HMAC_Update (&ctx, msg, 2);
  HMAC_Update (&ctx, (const uint8_t *)&fakelen, 2);
  /* first 4 bytes done, last 24 bytes not summed */
  HMAC_Update (&ctx, msg + 4, len - 28u);

  /* RFC 3489 specifies that the message's size should be 64 bytes,
     and \x00 padding should be done */
  if (padding && ((len - 24) % 64) > 0) {
    uint16_t pad_size = 64 - ((len - 24) % 64);
    int i;
    uint8_t pad_char[1] = {0};
    for (i = 0; i < pad_size; i++) {
      HMAC_Update (&ctx, pad_char, 1);
    }
  }

  HMAC_Final (&ctx, sha, NULL);
  HMAC_CTX_cleanup (&ctx);
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
  EVP_MD_CTX ctx;
  const uint8_t *username_trimmed = priv_trim_var (username, &username_len);
  const uint8_t *password_trimmed = priv_trim_var (password, &password_len);
  const uint8_t *realm_trimmed = priv_trim_var (realm, &realm_len);

  EVP_MD_CTX_init (&ctx);
  EVP_DigestInit_ex (&ctx, EVP_md5 (), NULL);
  EVP_DigestUpdate (&ctx, username_trimmed, username_len);
  EVP_DigestUpdate (&ctx, ":", 1);
  EVP_DigestUpdate (&ctx, realm_trimmed, realm_len);
  EVP_DigestUpdate (&ctx, ":", 1);
  EVP_DigestUpdate (&ctx, password_trimmed, password_len);
  EVP_DigestFinal (&ctx, md5, NULL);
}


void stun_make_transid (stun_transid_t id)
{
  RAND_bytes (id, 16);
}
