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
# include <config.h>
#endif

#include <string.h>

#include <nice/nice.h>

static GMainLoop *loop = NULL;

static void
recv_cb (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf,
  gpointer data)
{
  g_assert (agent != NULL);
  g_assert (stream_id == 1);
  g_assert (component_id == 1);
  g_assert (len == 6);
  g_assert (0 == strncmp (buf,  "\x80hello", len));
  g_assert (42 == GPOINTER_TO_UINT (data));
  g_main_loop_quit (loop);
}

int
main (void)
{
  NiceAgent *agent;
  NiceAddress addr;
  NiceUDPSocketFactory factory;

  nice_address_init (&addr);
  g_type_init ();

  nice_udp_fake_socket_factory_init (&factory);
  agent = nice_agent_new (&factory);
  nice_address_set_ipv4 (&addr, 0x7f000001);
  nice_agent_add_local_address (agent, &addr);
  nice_agent_add_stream (agent, 1);
  // attach to default main context
  nice_agent_main_context_attach (agent, NULL, recv_cb, GUINT_TO_POINTER (42));

    {
      NiceUDPSocket *sock;
      NiceCandidate *candidate;
      GSList *candidates;

      candidates = nice_agent_get_local_candidates (agent, 1, 1);
      candidate = candidates->data;
      sock = candidate->sockptr;
      g_slist_free (candidates);

      nice_udp_fake_socket_push_recv (sock, &addr, 6, "\x80hello");
    }

  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);

  g_object_unref (agent);
  nice_udp_socket_factory_close (&factory);
  return 0;
}

