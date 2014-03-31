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


#include "stun/sha1.h"
#include "stun/md5.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

static void print_bytes (const uint8_t *bytes, int len)
{
  int i;

  printf ("0x");
  for (i = 0; i < len; i++)
    printf ("%02x", bytes[i]);
  printf ("\n");
}

static void test_sha1 (const uint8_t *str, const uint8_t *expected) {
  SHA1_CTX ctx;
  uint8_t sha1[20];

  SHA1Init(&ctx);
  SHA1Update(&ctx, str, strlen ((char *) str));
  SHA1Final(sha1, &ctx);

  printf ("SHA1 of '%s' : ", str);
  print_bytes (sha1, SHA1_MAC_LEN);
  printf ("Expected : ");
  print_bytes (expected, SHA1_MAC_LEN);

  if (memcmp (sha1, expected, SHA1_MAC_LEN))
    exit (1);

}

static void test_hmac (const uint8_t *key, const uint8_t *str,
    const uint8_t *expected) {
  uint8_t hmac[20];

  hmac_sha1(key, strlen ((char *) key), str, strlen ((char *) str), hmac);
  printf ("HMAC of '%s' with key '%s' is : ", str, key);
  print_bytes (hmac, SHA1_MAC_LEN);
  printf ("Expected : ");
  print_bytes (expected, SHA1_MAC_LEN);

  if (memcmp (hmac, expected, SHA1_MAC_LEN))
    exit (1);
}

static void test_md5 (const uint8_t *str,  const uint8_t *expected) {
  MD5_CTX ctx;
  uint8_t md5[20];

  MD5Init(&ctx);
  MD5Update(&ctx, str, strlen ((char *) str));
  MD5Final(md5, &ctx);

  printf ("MD5 of '%s' : 0x", str);
  print_bytes (md5, MD5_MAC_LEN);
  printf ("Expected : ");
  print_bytes (expected, MD5_MAC_LEN);

  if (memcmp (md5, expected, MD5_MAC_LEN))
    exit (1);
}

int main (void)
{

  uint8_t hello_world_hmac[] = {0x8a, 0x3a, 0x84, 0xbc, 0xd0,
                                0xd0, 0x06, 0x5e, 0x97, 0xf1,
                                0x75, 0xd3, 0x70, 0x44, 0x7c,
                                0x7d, 0x02, 0xe0, 0x09, 0x73};
  uint8_t abc_sha1[] = {0xa9, 0x99, 0x3e, 0x36, 0x47,
                        0x06, 0x81, 0x6a, 0xba, 0x3e,
                        0x25, 0x71, 0x78, 0x50, 0xc2,
                        0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  uint8_t abcd_etc_sha1[] = {0x84, 0x98, 0x3e, 0x44, 0x1c,
                             0x3b, 0xd2, 0x6e, 0xba, 0xae,
                             0x4a, 0xa1, 0xf9, 0x51, 0x29,
                             0xe5, 0xe5, 0x46, 0x70, 0xf1};
  uint8_t abc_md5[] = {0x90, 0x01, 0x50, 0x98,
                       0x3c, 0xd2, 0x4f, 0xb0,
                       0xd6, 0x96, 0x3f, 0x7d,
                       0x28, 0xe1, 0x7f, 0x72};
  uint8_t abcd_etc_md5[] = {0x82, 0x15, 0xef, 0x07,
                            0x96, 0xa2, 0x0b, 0xca,
                            0xaa, 0xe1, 0x16, 0xd3,
                            0x87, 0x6c, 0x66, 0x4a};

  test_hmac ((const uint8_t *) "hello", (const uint8_t*) "world",
      hello_world_hmac);

  test_sha1 ((const uint8_t *) "abc", abc_sha1);
  test_md5 ((const uint8_t *) "abc", abc_md5);

  test_sha1 ((const uint8_t *)
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", abcd_etc_sha1);
  test_md5 ((const uint8_t *)
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", abcd_etc_md5);

  return 0;
}
