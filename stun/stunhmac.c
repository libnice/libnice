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
#include <gcrypt.h>

void stun_sha1 (const uint8_t *msg, size_t len, size_t msg_len, uint8_t *sha,
    const void *key, size_t keylen, int padding)
{
  uint16_t fakelen = htons (msg_len);
  uint8_t pad_char[64] = {0};
  gcry_mac_hd_t hd;
  size_t sha_len = 20;

#define TRY(s) \
  if (!(s)) \
    abort ();

  assert (len >= 44u);

  TRY (gcry_mac_open (&hd, GCRY_MAC_HMAC_SHA1, 0  /* flags */, NULL) == 0);
  TRY (gcry_mac_setkey (hd, key, keylen) == 0);

  TRY (gcry_mac_write (hd, msg, 2) == 0);
  TRY (gcry_mac_write (hd, &fakelen, 2) == 0);
  TRY (gcry_mac_write (hd, msg + 4, len - 28) == 0);

  /* RFC 3489 specifies that the message's size should be 64 bytes,
     and \x00 padding should be done */
  if (padding && ((len - 24) % 64) > 0) {
    uint16_t pad_size = 64 - ((len - 24) % 64);
    TRY (gcry_mac_write (hd, pad_char, pad_size) == 0);
  }

  TRY (gcry_mac_read (hd, sha, &sha_len) == 0);
  assert (sha_len == 20);

  gcry_mac_close (hd);
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

  /* https://gnupg.org/documentation/manuals/gcrypt/Buffer-description.html */
  const gcry_buffer_t iov[] = {
      /* size, off, len, data */
      { 0, 0, username_len, (void *) username_trimmed },
      { 0, 0, 1, (void *) colon },
      { 0, 0, realm_len, (void *) realm_trimmed },
      { 0, 0, 1, (void *) colon },
      { 0, 0, password_len, (void *) password_trimmed },
  };

  gcry_md_hash_buffers (GCRY_MD_MD5, 0  /* flags */, md5,
                        iov, sizeof (iov) / sizeof (*iov));
}


void stun_make_transid (StunTransactionId id)
{
  nice_RAND_bytes (id, 16);
}
