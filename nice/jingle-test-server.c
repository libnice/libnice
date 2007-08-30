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

/*
 * This program interoperates with the test-rtp-jingle program from the
 * Farsight tests/ directory. It echoes received media to the sender.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <nice/nice.h>

static void
recv_cb (
  NiceAgent *agent,
  guint stream_id,
  guint candidate_id,
  guint len,
  gchar *buf,
  G_GNUC_UNUSED
  gpointer user_data)
{
  nice_agent_send (agent, stream_id, candidate_id, len, buf);
}

static NiceAgent *
make_agent (NiceUDPSocketFactory *factory)
{
  NiceAgent *agent;
  NiceAddress addr;

  agent = nice_agent_new (factory);

  if (!nice_address_set_from_string (&addr, "127.0.0.1"))
    g_assert_not_reached ();

  nice_agent_add_local_address (agent, &addr);
  nice_agent_add_stream (agent, 1);
  return agent;
}

static guint
accept_connection (
  NiceUDPSocketFactory *factory,
  NiceUDPSocket *sock)
{
  NiceAgent *agent;
  NiceAddress recv_addr;
  NiceAddress send_addr;
  guint len;
  gchar buf[1024];
  guint ret = 0;
  GSList *fds = NULL;

  agent = make_agent (factory);

  // accept incoming handshake

  len = nice_udp_socket_recv (sock, &recv_addr, 1, buf);

  if (len != 1)
    {
      ret = 1;
      goto OUT;
    }

  if (buf[0] != '2')
    {
      ret = 2;
      goto OUT;
    }

  g_debug ("got handshake packet");

  // send handshake reply

  send_addr = recv_addr;
  send_addr.port = 1235;
  nice_udp_socket_send (sock, &send_addr, 1, buf);

  // send codec

  strcpy (buf, "1 0 PCMU 0 8000 0");
  nice_udp_socket_send (sock, &send_addr, strlen (buf), buf);
  strcpy (buf, "1 0 LAST 0 0 0");
  nice_udp_socket_send (sock, &send_addr, strlen (buf), buf);

  // send candidate

    {
      NiceCandidate *candidate;
      GSList *candidates;

      candidates = nice_agent_get_local_candidates (agent, 1, 1);
      candidate = candidates->data;
      len = g_snprintf (buf, 1024, "0 0 X1 127.0.0.1 %d %s %s",
          candidate->addr.port, candidate->username, candidate->password);
      nice_udp_socket_send (sock, &send_addr, len, buf);
      g_slist_free (candidates);
    }

  // IO loop

  fds = g_slist_append (fds, GUINT_TO_POINTER (sock->fileno));

  for (;;)
    {
      gchar **bits;
      NiceAddress addr;

      if (nice_agent_poll_read (agent, fds, recv_cb, NULL) == NULL)
        continue;

      len = nice_udp_socket_recv (sock, &recv_addr, 1024, buf);
      buf[len] = '\0';
      g_debug ("%s", buf);

      if (buf[0] != '0')
        continue;

      bits = g_strsplit (buf, " ", 7);

      if (g_strv_length (bits) != 7)
        {
          g_strfreev (bits);
          return 3;
        }

      if (!nice_address_set_from_string (&addr, bits[3]))
        g_assert_not_reached ();

      addr.port = atoi (bits[4]);
      g_debug ("username = %s", bits[5]);
      g_debug ("password = %s", bits[6]);
      nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
          &addr, bits[5], bits[6]);
    }

OUT:
  g_slist_free (fds);
  g_object_unref (agent);
  return ret;
}

int
main (void)
{
  NiceUDPSocketFactory factory;
  NiceUDPSocket sock;
  NiceAddress addr;
  guint ret;

  memset (&addr, 0, sizeof (addr));
  g_type_init ();

  addr.port = 1234;

  nice_udp_bsd_socket_factory_init (&factory);

  if (!nice_udp_socket_factory_make (&factory, &sock, &addr))
    g_assert_not_reached ();

  ret = accept_connection (&factory, &sock);
  nice_udp_socket_close (&sock);
  nice_udp_socket_factory_close (&factory);
  return ret;
}

