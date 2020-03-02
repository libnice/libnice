/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2020 Fabrice Bellet <fabrice@bellet.info>
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
#include <address.h>
#include "../agent/interfaces.c"

#ifdef G_OS_UNIX
static void
test_ipv4 (void)
{
  NiceAddress addr;
  union {
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
  } sin;

  /* test private addresses */
  nice_address_set_from_string (&addr, "10.1.2.3");
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_interfaces_is_private_ip (&sin.addr));

  nice_address_set_from_string (&addr, "172.22.22.22");
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_interfaces_is_private_ip (&sin.addr));

  nice_address_set_from_string (&addr, "192.168.122.1");
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_interfaces_is_private_ip (&sin.addr));

  nice_address_set_from_string (&addr, "169.254.1.2");
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_interfaces_is_private_ip (&sin.addr));

  /* test public addresses */
  nice_address_set_from_string (&addr, "1.2.3.4");
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_interfaces_is_private_ip (&sin.addr) == FALSE);

}

static void
test_ipv6 (void)
{
  NiceAddress addr;
  union {
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
  } sin;

  /* test private addresses */
  nice_address_set_from_string (&addr,
      "fe8f:2233:4455:6677:8899:aabb:ccdd:eeff");
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_interfaces_is_private_ip (&sin.addr));

  /* test public addresses */
  nice_address_set_from_string (&addr,
      "11:2233:4455:6677:8899:aabb:ccdd:eeff");
  nice_address_copy_to_sockaddr (&addr, &sin.addr);
  g_assert (nice_interfaces_is_private_ip (&sin.addr) == FALSE);
}
#endif /* G_OS_UNIX */

int
main (void)
{
#ifdef G_OS_UNIX
  test_ipv4 ();
  test_ipv6 ();
#endif
  return 0;
}

