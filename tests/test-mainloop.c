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
#include "socket/socket.h"

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
  guint stream;

  nice_address_init (&addr);
  g_type_init ();
  g_thread_init(NULL);

  loop = g_main_loop_new (NULL, FALSE);

  agent = nice_agent_new (g_main_loop_get_context (loop), NICE_COMPATIBILITY_RFC5245);
  nice_address_set_ipv4 (&addr, 0x7f000001);
  nice_agent_add_local_address (agent, &addr);
  stream = nice_agent_add_stream (agent, 1);
  nice_agent_gather_candidates (agent, stream);

  // attach to default main context
  nice_agent_attach_recv (agent, stream, NICE_COMPONENT_TYPE_RTP,
      g_main_loop_get_context (loop), recv_cb, GUINT_TO_POINTER (42));

    {
      NiceCandidate *candidate;
      GSList *candidates, *i;

      candidates = nice_agent_get_local_candidates (agent, 1, 1);
      candidate = candidates->data;

      nice_socket_send (candidate->sockptr, &(candidate->addr), 6, "\x80hello");
      for (i = candidates; i; i = i->next)
        nice_candidate_free ((NiceCandidate *) i->data);
      g_slist_free (candidates);
    }

  g_main_loop_run (loop);

  nice_agent_remove_stream (agent, stream);
  g_object_unref (agent);

  return 0;
}

