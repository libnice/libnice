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

#include <unistd.h>

#include <nice/nice.h>

static gboolean cb_called = FALSE;

static void
handle_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf,
  gpointer data)
{
  g_assert (agent != NULL);
  g_assert (cb_called == FALSE);
  g_assert (stream_id == 1);
  g_assert (component_id == 1);
  g_assert (len == 7);
  g_assert (0 == strncmp (buf, "\x80lalala", 7));
  g_assert (GPOINTER_TO_UINT (data) == 42);
  cb_called = TRUE;
}

int
main (void)
{
  NiceAgent *agent;
  NiceAddress addr;
  NiceUDPSocketFactory factory;
  NiceUDPSocket *sock;
  gint pipe_fds[2];
  GSList *fds = NULL;
  GSList *readable;
  ssize_t w;
  guint stream_id;

  nice_address_init (&addr);
  g_type_init ();
  g_thread_init (NULL);

  /* set up agent */

  if (!nice_address_set_from_string (&addr, "127.0.0.1"))
    g_assert_not_reached ();

  nice_udp_fake_socket_factory_init (&factory);
  agent = nice_agent_new (&factory, NULL, NICE_COMPATIBILITY_ID19);
  nice_agent_add_local_address (agent, &addr);
  stream_id = nice_agent_add_stream (agent, 1);
  nice_agent_gather_candidates (agent, stream_id);

      {
        GSList *candidates;
        NiceCandidate *candidate;

        candidates = nice_agent_get_local_candidates (agent, stream_id, 1);
        candidate = candidates->data;
        sock = candidate->sockptr;
        g_slist_free (candidates);
      }

  /* set up pipe and fd list */

  if (pipe (pipe_fds) != 0)
    g_assert_not_reached ();

  w = write (pipe_fds[1], "hello", 5);
  g_assert (w == 5);

  fds = g_slist_append (fds, GUINT_TO_POINTER (pipe_fds[0]));

  /* poll */

  readable = nice_agent_poll_read (agent, fds, NULL, NULL);
  g_assert (g_slist_length (readable) == 1);
  g_assert (GPOINTER_TO_UINT (readable->data) == (guint) pipe_fds[0]);
  g_slist_free (readable);
  g_assert (cb_called == FALSE);

   {
     gchar buf[1024];

     g_assert (5 == read (pipe_fds[0], buf, 1024));
     g_assert (0 == strncmp (buf, "hello", 5));
   }

  /* send fake data */

  nice_udp_fake_socket_push_recv (sock, &addr, 7, "\x80lalala");

  /* poll again */

  readable = nice_agent_poll_read (agent, fds, handle_recv,
      GUINT_TO_POINTER (42));
  g_assert (cb_called == TRUE);
  g_assert (readable == NULL);

  /* clean up */

  g_slist_free (fds);
  g_object_unref (agent);

  return 0;
}

