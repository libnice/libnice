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


#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <stun/stunhmac.h>

static void print_bytes (const uint8_t *bytes, int len)
{
  int i;

  printf ("0x");
  for (i = 0; i < len; i++)
    printf ("%02x", bytes[i]);
  printf ("\n");
}

static void test_hmac (const uint8_t *key, const uint8_t *str,
    const uint8_t *expected) {
  uint8_t hmac[20];

  /* Arbitrary. */
  size_t msg_len = 300;

  stun_sha1 (str, strlen ((const char *) str), msg_len, hmac,
             key, strlen ((const char *) key), TRUE  /* padding */);

  printf ("HMAC of '%s' with key '%s' is : ", str, key);
  print_bytes (hmac, sizeof (hmac));
  printf ("Expected : ");
  print_bytes (expected, sizeof (hmac));

  if (memcmp (hmac, expected, sizeof (hmac)))
    exit (1);
}

int main (void)
{
  const uint8_t hmac1[] = { 0x83, 0x5a, 0x9b, 0x05, 0xea,
                            0xd7, 0x68, 0x45, 0x48, 0x74,
                            0x6b, 0xa3, 0x37, 0xe0, 0xa9,
                            0x3f, 0x4d, 0xb3, 0x9c, 0xa1 };

  test_hmac ((const uint8_t *) "key",
             (const uint8_t *) "some complicated input string which is over 44 bytes long",
             hmac1);

  return 0;
}
