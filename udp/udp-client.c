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
#include <stdio.h>

#include "udp-bsd.h"

gint
main (void)
{
  NiceUDPSocketFactory man;
  NiceUDPSocket sock;
  NiceAddress addr;

  nice_udp_bsd_socket_factory_init (&man);

  if (!nice_udp_socket_factory_make (&man, &sock, NULL))
    g_assert_not_reached ();

  if (!nice_address_set_ipv4_from_string (&addr, "127.0.0.1"))
    g_assert_not_reached ();

  addr.port = 9999;

  for (;;)
    {
      gchar buf[1024];
      guint length;

      if (fgets (buf, sizeof (buf), stdin) == NULL)
        break;

      nice_udp_socket_send (&sock, &addr, strlen (buf), buf);
      length = nice_udp_socket_recv (&sock, &addr, sizeof (buf), buf);
      g_print (buf);
    }

  nice_udp_socket_close (&sock);
  nice_udp_socket_factory_close (&man);
  return 0;
}

