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

#include <unistd.h>
#include <arpa/inet.h>

#include <glib/gprintf.h>

#include "nice.h"
#include "readline.h"
#include "util.h"
#include "stun.h"

static void
send_stun (NiceUDPSocket *udpsock, NiceAddress addr, gchar *username)
{
  gchar *packed;
  guint packed_len;
  gchar buf[1024];
  StunMessage *msg;

  msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST, NULL, 1);
  msg->attributes[0] = stun_attribute_username_new (username);

    {
      gchar *dump;
      dump = stun_message_dump (msg);
      g_debug ("sending message:\n%s", dump);
      g_free (dump);
    }

  packed_len = stun_message_pack (msg, &packed);
  nice_udp_socket_send (udpsock, &addr, packed_len, packed);
  g_free (packed);
  stun_message_free (msg);

  packed_len = nice_udp_socket_recv (udpsock, &addr, 1024, buf);
  g_assert (packed_len > 0);
  msg = stun_message_unpack (packed_len, buf);
  g_assert (msg);

    {
      gchar *dump;
      dump = stun_message_dump (msg);
      g_debug ("got response:\n%s", dump);
      g_free (dump);
    }

  stun_message_free (msg);
}

static void
handle_connection (guint sock)
{
  gchar *line;
  NiceUDPSocketFactory man;
  NiceUDPSocket udpsock;
  NiceCandidate *candidate;

  // recieve and parse remote candidate

  line = readline (sock);

  if (line == NULL)
    return;

  candidate = nice_candidate_from_string (line);

  if (candidate == NULL)
    return;

  g_debug ("got candidate: %s", line);
  g_free (line);

  // create local UDP port

  nice_udp_bsd_socket_factory_init (&man);

  if (!nice_udp_socket_factory_make (&man, &udpsock, NULL))
    goto OUT;

  // send local candidate

  line = g_strdup_printf ("H/127.0.0.1/%d/lala/titi\n",
      ntohs (udpsock.addr.port));

  if (write (sock, line, strlen (line)) != (gint) strlen (line))
    g_assert_not_reached ();

  g_free (line);

  // agent doesn't initiate connectivity checks, so make our own for now

    {
      gchar *username;

      username = g_strdup_printf ("%slala", candidate->username);
      send_stun (&udpsock, candidate->addr, username);
      g_free (username);
    }

  nice_udp_socket_send (&udpsock, &candidate->addr, 6, "\x80hello");
  nice_udp_socket_close (&udpsock);

OUT:
  nice_udp_socket_factory_close (&man);
  nice_candidate_free (candidate);
}

int
main (gint argc, gchar *argv[])
{
  struct sockaddr_in sin = {0,};
  gint sock;

  sock = socket (AF_INET, SOCK_STREAM, 0);

  if (argc != 2)
    {
      g_print ("usage: %s server\n", argv[0]);
      return 1;
    }

  if (sock < 0)
    {
      g_print ("failed to create socket\n");
      return 1;
    }

  if (inet_pton (AF_INET, argv[1], &sin.sin_addr) < 1)
    {
      g_print ("invalid address\n");
      return 1;
    }

  sin.sin_family = AF_INET;
  sin.sin_port = htons (7899);

  if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) != 0)
    {
      g_print ("failed to connect\n");
      return 1;
    }

  handle_connection (sock);
  close (sock);
  return 0;
}

