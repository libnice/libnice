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
 *   Kai Vehmanen, Nokia
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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "address.h"

static void
test_ipv4 (void)
{
  NiceAddress addr;
  NiceAddress other;
  gchar str[NICE_ADDRESS_STRING_LEN];
  struct sockaddr_in sin;

  sin.sin_family = AF_INET;
  sin.sin_port = htons (9876);
  g_assert (inet_pton (AF_INET, "1.2.3.4", &sin.sin_addr) > 0);

  memset (&addr, 0, sizeof (addr));
  memset (&other, 0, sizeof (other));
  nice_address_set_ipv4 (&addr, 0x01020304);
  g_assert (addr.type == NICE_ADDRESS_TYPE_IPV4);

  nice_address_to_string (&addr, str);
  g_assert (0 == strcmp (str, "1.2.3.4"));

  nice_address_to_string (&addr, str);

  /* same address */
  nice_address_set_ipv4 (&other, 0x01020304);
  g_assert (TRUE == nice_address_equal (&addr, &other));

  /* from sockaddr_in */
  other.port = 9876; /* in native byte order */
  other.type = NICE_ADDRESS_TYPE_IPV4;
  nice_address_set_from_sockaddr (&addr, (struct sockaddr*)&sin);
  nice_address_to_string (&addr, str);
  nice_address_to_string (&other, str);
  g_assert (TRUE == nice_address_equal (&addr, &other));

  /* different IP */
  nice_address_set_ipv4 (&other, 0x01020305);
  g_assert (FALSE == nice_address_equal (&addr, &other));

  /* different port */
  nice_address_set_ipv4 (&other, 0x01020304);
  addr.port = 1;
  g_assert (FALSE == nice_address_equal (&addr, &other));
}

static void
test_ipv6 (void)
{
  NiceAddress addr, other;
  gchar str[NICE_ADDRESS_STRING_LEN];
  struct sockaddr_in6 sin;

  sin.sin6_family = AF_INET6;
  sin.sin6_port = htons (9876);
  g_assert (inet_pton (AF_INET6, "11:2233:4455:6677:8899:aabb:ccdd:eeff", &sin.sin6_addr) > 0);

  memset (&addr, 0, sizeof (addr));
  nice_address_set_ipv6 (&addr,
      "\x00\x11\x22\x33"
      "\x44\x55\x66\x77"
      "\x88\x99\xaa\xbb"
      "\xcc\xdd\xee\xff");
  g_assert (addr.type == NICE_ADDRESS_TYPE_IPV6);

  nice_address_to_string (&addr, str);
  g_assert (0 == strcmp (str, "11:2233:4455:6677:8899:aabb:ccdd:eeff"));

  addr.port = 9876; /* in native byte order */
  nice_address_set_from_sockaddr (&other, (struct sockaddr*)&sin);
  nice_address_to_string (&addr, str);
  nice_address_to_string (&other, str);
  g_assert (TRUE == nice_address_equal (&addr, &other));
}

int
main (void)
{
  test_ipv4 ();
  test_ipv6 ();
  return 0;
}

