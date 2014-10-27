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

#include "sha1.h"
#include "md5.h"
#include "rand.h"

#include "stunmessage.h"
#include "stunhmac.h"

#include <string.h>
#include <assert.h>

void stun_sha1 (const uint8_t *msg, size_t len, size_t msg_len, uint8_t *sha,
    const void *key, size_t keylen, int padding)
{
  uint16_t fakelen = htons (msg_len);
  const uint8_t *vector[4];
  size_t lengths[4];
  uint8_t pad_char[64] = {0};
  size_t num_elements;

  assert (len >= 44u);

  vector[0] = msg;
  lengths[0] = 2;
  vector[1] = (const uint8_t *)&fakelen;
  lengths[1] = 2;
  vector[2] = msg + 4;
  lengths[2] = len - 28;
  num_elements = 3;

  /* RFC 3489 specifies that the message's size should be 64 bytes,
     and \x00 padding should be done */
  if (padding && ((len - 24) % 64) > 0) {
    uint16_t pad_size = 64 - ((len - 24) % 64);

    vector[3] = pad_char;
    lengths[3] = pad_size;
    num_elements++;
  }

  hmac_sha1_vector(key, keylen, num_elements, vector, lengths, sha);
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
  MD5_CTX ctx;
  const uint8_t *username_trimmed = priv_trim_var (username, &username_len);
  const uint8_t *password_trimmed = priv_trim_var (password, &password_len);
  const uint8_t *realm_trimmed = priv_trim_var (realm, &realm_len);
  const uint8_t *colon = (uint8_t *)":";

  MD5Init (&ctx);
  MD5Update (&ctx, username_trimmed, username_len);
  MD5Update (&ctx, colon, 1);
  MD5Update (&ctx, realm_trimmed, realm_len);
  MD5Update (&ctx, colon, 1);
  MD5Update (&ctx, password_trimmed, password_len);
  MD5Final (md5, &ctx);
}


void stun_make_transid (StunTransactionId id)
{
  nice_RAND_bytes (id, 16);
}
