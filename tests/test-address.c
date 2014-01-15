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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "address.h"

static void
test_ipv4 (void)
{
  NiceAddress addr;
  NiceAddress other;
  gchar str[NICE_ADDRESS_STRING_LEN];

  nice_address_init (&addr);
  nice_address_init (&other);
  nice_address_set_ipv4 (&addr, 0x01020304);
  g_assert (addr.s.ip4.sin_family == AF_INET);

  nice_address_to_string (&addr, str);
  g_assert (0 == strcmp (str, "1.2.3.4"));

  nice_address_to_string (&addr, str);

  /* same address */
  nice_address_set_ipv4 (&other, 0x01020304);
  g_assert (TRUE == nice_address_equal (&addr, &other));

  /* from sockaddr_in */
  nice_address_set_port (&other, 9876); /* in native byte order */
  other.s.ip4.sin_family = AF_INET;
  nice_address_set_from_string (&addr, "1.2.3.4");
  nice_address_set_port (&addr, 9876); /* in native byte order */
  nice_address_to_string (&addr, str);
  nice_address_to_string (&other, str);
  g_assert (TRUE == nice_address_equal (&addr, &other));

  /* different IP */
  nice_address_set_ipv4 (&other, 0x01020305);
  g_assert (FALSE == nice_address_equal (&addr, &other));

  /* different port */
  nice_address_set_ipv4 (&other, 0x01020304);
  nice_address_set_port (&addr, 1);
  g_assert (FALSE == nice_address_equal (&addr, &other));

  /* test private address check */
  {
    NiceAddress *heap_addr = nice_address_new ();
    g_assert (nice_address_set_from_string (heap_addr, "127.0.0.1") == TRUE);
    g_assert (nice_address_is_private (heap_addr) == TRUE);
    g_assert (nice_address_set_from_string (heap_addr, "127.0.0.1.1") != TRUE);
    nice_address_free (heap_addr);
  }
}

static void
test_ipv6 (void)
{
  NiceAddress addr, other, v4addr;
  gchar str[NICE_ADDRESS_STRING_LEN];
  union {
    struct sockaddr_in6 in6;
    struct sockaddr addr;
  } sin, sin2;

  g_assert (nice_address_set_from_string (&v4addr, "172.1.0.1") == TRUE);

  memset (&sin, 0, sizeof (sin));
  memset (&sin2, 0, sizeof (sin2));

  memset (&addr, 0, sizeof (NiceAddress));
  memset (&other, 0, sizeof (NiceAddress));
  nice_address_init (&addr);
  nice_address_init (&other);
  nice_address_set_ipv6 (&addr, (guchar *)
      "\x00\x11\x22\x33"
      "\x44\x55\x66\x77"
      "\x88\x99\xaa\xbb"
      "\xcc\xdd\xee\xff");
  g_assert (addr.s.ip6.sin6_family == AF_INET6);

  nice_address_to_string (&addr, str);
  g_assert (0 == strcmp (str, "11:2233:4455:6677:8899:aabb:ccdd:eeff"));

  nice_address_set_port (&addr, 9876); /* in native byte order */
  nice_address_set_from_string (&other, "11:2233:4455:6677:8899:aabb:ccdd:eeff");
  nice_address_set_port (&other, 9876); /* in native byte order */

  nice_address_copy_to_sockaddr (&other, &sin2.addr);
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_address_equal (&addr, &other) == TRUE);
  nice_address_to_string (&addr, str);
  nice_address_to_string (&other, str);

  g_assert (memcmp (&sin, &sin2, sizeof(sin)) == 0);

  /* private IPv6 address */
  nice_address_set_ipv6 (&addr, (guchar *)
      "\xfc\x00\x00\x00"
      "\x00\x00\x00\x00"
      "\x00\x00\x00\x00"
      "\x00\x00\x00\x01");
  g_assert (nice_address_is_private (&addr) == TRUE);
  nice_address_set_ipv6 (&addr, (guchar *)
      "\x00\x00\x00\x00"
      "\x00\x00\x00\x00"
      "\x00\x00\x00\x00"
      "\x00\x00\x00\x01");
  g_assert (nice_address_is_private (&addr) == TRUE);

  /* mismatching address families */
  g_assert (nice_address_equal (&addr, &v4addr) != TRUE);

  /* mismatched type */
  addr.s.addr.sa_family = AF_UNSPEC;
  /*g_assert (nice_address_equal (&addr, &v4addr) != TRUE);*/
}

int
main (void)
{
#ifdef G_OS_WIN32
  WSADATA w;
#endif

#ifdef G_OS_WIN32
  WSAStartup(0x0202, &w);
#endif
  test_ipv4 ();
  test_ipv6 ();

#ifdef G_OS_WIN32
  WSACleanup();
#endif
  return 0;
}

