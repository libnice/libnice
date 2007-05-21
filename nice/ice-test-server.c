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

#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "nice.h"
#include "readline.h"
#include "util.h"

static void
handle_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf, gpointer user_data)
{
  g_debug ("got media");
  (void)agent; (void)stream_id; (void)component_id; (void)len; (void)buf;
  (void)user_data;
}

/* create an agent and give it one fixed local IP address */
static gboolean
make_agent (
  gchar *ip,
  NiceUDPSocketFactory *factory,
  NiceAgent **ret_agent,
  NiceUDPSocket **ret_sock)
{
  NiceAgent *agent;
  NiceAddress addr_local;
  NiceCandidate *candidate;
  GSList *candidates;

  agent = nice_agent_new (factory);

  if (!nice_address_set_ipv4_from_string (&addr_local, ip))
    g_assert_not_reached ();

  nice_agent_add_local_address (agent, &addr_local);
  nice_agent_add_stream (agent, 1);

  candidates = nice_agent_get_local_candidates (agent, 1, 1);
  g_assert (candidates != NULL);
  candidate = candidates->data;
  g_debug ("allocated socket %d port %d for candidate %s",
      candidate->sockptr->fileno, candidate->sockptr->addr.port, candidate->foundation);
  g_slist_free (candidates);

  *ret_agent = agent;
  *ret_sock = candidate->sockptr;

  return TRUE;
}

static gboolean
handle_tcp_read (guint fileno, NiceAgent *agent)
{
  NiceCandidate *candidate;
  gchar *line;

  line = readline (fileno);

  if (line == NULL)
    /* EOF */
    return FALSE;

  candidate = nice_candidate_from_string (line);

  if (candidate == NULL)
    /* invalid candidate string */
    return FALSE;

  g_debug ("got remote candidate: %s", line);
  nice_agent_add_remote_candidate (agent, 1, 1, candidate->type,
      &candidate->addr, candidate->username, candidate->password);
  nice_candidate_free (candidate);
  g_free (line);

  return TRUE;
}

static void
handle_connection (guint fileno, const struct sockaddr_in *sin, gpointer data)
{
  NiceAgent *agent;
  NiceUDPSocketFactory factory;
  NiceUDPSocket *sock;
  gchar ip_str[INET_ADDRSTRLEN];
  gchar *candidate_str;
  GSList *in_fds = NULL;

  inet_ntop (AF_INET, &(sin->sin_addr), ip_str, INET_ADDRSTRLEN);
  g_debug ("got connection from %s:%d", ip_str, ntohs (sin->sin_port));

  nice_udp_bsd_socket_factory_init (&factory);

  if (!make_agent ((gchar *) data, &factory, &agent, &sock))
    return;

    {
      GSList *candidates;

      /* send first local candidate to remote end */
      candidates = nice_agent_get_local_candidates (agent, 1, 1);
      candidate_str = nice_candidate_to_string (candidates->data);
      send (fileno, candidate_str, strlen (candidate_str), 0);
      send (fileno, "\n", 1, 0);
      g_free (candidate_str);
      g_slist_free (candidates);
    }

  /* event loop */

  in_fds = g_slist_append (in_fds, GUINT_TO_POINTER (fileno));

  for (;;)
    {
      GSList *out_fds;
      GSList *i;

      out_fds = nice_agent_poll_read (agent, in_fds, handle_recv, NULL);

      for (i = out_fds; i; i = i->next)
        if (GPOINTER_TO_UINT (i->data) == fileno)
          {
            /* TCP data */

            g_debug ("got TCP data");

            if (!handle_tcp_read (fileno, agent))
              goto END;
          }

      g_slist_free (out_fds);
    }

END:
  g_debug ("-- connection closed --");

  g_slist_free (in_fds);
  nice_udp_socket_factory_close (&factory);
  g_object_unref (agent);
}

static gboolean
tcp_listen_loop (
  guint port,
  void (*handler) (guint sock, const struct sockaddr_in *sin, gpointer data),
  gpointer data)
{
  gint sock;
  struct sockaddr_in sin;

  sock = socket (AF_INET, SOCK_STREAM, 0);

  if (sock < 0)
    {
      g_print ("socket() failed: %s\n", g_strerror (errno));
      return FALSE;
    }

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons (port);

  if (bind (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
      g_print ("bind() failed: %s\n", g_strerror (errno));
      return 1;
    }

  if (listen (sock, 5) < 0)
    {
      g_print ("listen() failed: %s\n", g_strerror (errno));
      return FALSE;
    }

  for (;;)
    {
      gint conn;
      struct sockaddr_in from;
      guint from_len = sizeof (from);

      conn = accept (sock, (struct sockaddr *) &from, &from_len);

      if (conn < 0)
        {
          g_print ("accept() failed: %s\n", g_strerror (errno));
          return FALSE;
        }

      handler (conn, &from, data);
      close (conn);
    }

  return TRUE;
}

int
main (int argc, char **argv)
{
  g_type_init ();

  if (argc != 2)
    {
      g_print ("usage: %s interface\n", argv[0]);
      return 1;
    }

  if (!tcp_listen_loop (7899, handle_connection, argv[1]))
    return 1;

  return 0;
}

