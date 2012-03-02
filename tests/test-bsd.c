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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "socket.h"

int
main (void)
{
  NiceSocket *server;
  NiceSocket *client;
  NiceAddress tmp;
  gchar buf[5];

  g_type_init ();
  server = nice_udp_bsd_socket_new (NULL);
  if (!server)
    g_assert_not_reached();

  // not bound to a particular interface
  g_assert (server->addr.s.ip4.sin_addr.s_addr == 0);
  // is bound to a particular port
  g_assert (nice_address_get_port (&server->addr) != 0);

  g_assert ((client = nice_udp_bsd_socket_new (NULL)) != NULL);
  // not bound to a particular interface
  g_assert (client->addr.s.ip4.sin_addr.s_addr == 0);
  // is bound to a particular port
  g_assert (nice_address_get_port (&client->addr) != 0);

  if (!nice_address_set_from_string (&tmp, "127.0.0.1"))
    g_assert_not_reached();
  g_assert (nice_address_get_port (&server->addr) != 0);
  nice_address_set_port (&tmp, nice_address_get_port (&server->addr));
  g_assert (nice_address_get_port (&tmp) != 0);

  nice_socket_send (client, &tmp, 5, "hello");

  g_assert (5 == nice_socket_recv (server, &tmp, 5, buf));
  g_assert (0 == strncmp (buf, "hello", 5));
  g_assert (nice_address_get_port (&tmp)
             == nice_address_get_port (&client->addr));

  nice_socket_send (server, &tmp, 5, "uryyb");
  g_assert (5 == nice_socket_recv (client, &tmp, 5, buf));
  g_assert (0 == strncmp (buf, "uryyb", 5));
  g_assert (nice_address_get_port (&tmp)
             == nice_address_get_port (&server->addr));

  nice_socket_free (client);
  nice_socket_free (server);
  return 0;
}

