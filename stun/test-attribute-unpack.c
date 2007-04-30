/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
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
 *   Dafydd Harries, Collabora Ltd.
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

#include <string.h>

#include "stun.h"

int
main (void)
{
  StunAttribute *attr;

  attr = stun_attribute_unpack (12,
    "\x00\x01"         // type
    "\x00\x08"         // length
    "\x00\x01"         // padding, address family
    "\x09\x29"         // port
    "\x02\x03\x04\x05" // IP address
    );

  g_assert (NULL != attr);
  g_assert (attr->type == STUN_ATTRIBUTE_MAPPED_ADDRESS);
  // length is not used
  g_assert (attr->length == 0);
  g_assert (attr->address.af == 1);
  g_assert (attr->address.port == 2345);
  g_assert (attr->address.ip == 0x02030405);
  stun_attribute_free (attr);

  attr = stun_attribute_unpack (9,
      "\x00\x06" // type
      "\x00\x05" // length
      "abcde"    // value
      );

  g_assert (NULL != attr);
  g_assert (attr->length == 5);
  g_assert (attr->type == STUN_ATTRIBUTE_USERNAME);
  g_assert (0 == memcmp (attr->username, "abcde", 5));
  stun_attribute_free (attr);

  attr = stun_attribute_unpack (10,
      "\x00\x07" // type
      "\x00\x06" // length
      "fghijk"   // value
      );

  g_assert (NULL != attr);
  g_assert (attr->length == 6);
  g_assert (attr->type == STUN_ATTRIBUTE_PASSWORD);
  g_assert (0 == memcmp (attr->password, "fghijk", 6));
  stun_attribute_free (attr);

  return 0;
}

