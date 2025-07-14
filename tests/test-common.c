/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2025 Axis Communications AB.
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
 *   Martin Nordholts, Axis Communications AB, 2025.
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

#include <agent.h>
#include <glib.h>

#include "test-common.h"

void
test_common_set_credentials (NiceAgent *lagent, guint lstream, NiceAgent *ragent, guint rstream)
{
  gchar *ufrag = NULL, *password = NULL;

  nice_agent_get_local_credentials (lagent, lstream, &ufrag, &password);
  nice_agent_set_remote_credentials (ragent, rstream, ufrag, password);
  g_free (ufrag);
  g_free (password);
  nice_agent_get_local_credentials (ragent, rstream, &ufrag, &password);
  nice_agent_set_remote_credentials (lagent, lstream, ufrag, password);
  g_free (ufrag);
  g_free (password);
}

gboolean
test_common_wait_for_tcp_socket (const gchar *service_name, const gchar *host, guint16 port)
{
  GSocketClient *client = g_socket_client_new ();
  int attempts_left = 50;
  gboolean connected = FALSE;

  while (!connected && attempts_left > 0) {
    attempts_left--;

    GError *err = NULL;
    GSocketConnection *conn = g_socket_client_connect_to_host (client, host, port, NULL, &err);
    if (conn) {
      g_debug ("%s ready at %s:%u", service_name, host, port);
      connected = TRUE;
      g_object_unref (conn);
    } else {
      gulong ms_to_wait = 100;
      g_usleep (ms_to_wait * 1000);
      g_debug (
          "%s at %s:%u not ready yet (%lu ms until next try; %d tries left): %s",
          service_name,
          host,
          port,
          ms_to_wait,
          attempts_left,
          err->message);
    }
    g_clear_error (&err);
  }

  g_object_unref (client);

  return connected;
}

gboolean
test_common_turnserver_available (void)
{
  gchar *out_str = NULL;
  gchar *err_str = NULL;

  gboolean available =
      g_spawn_command_line_sync ("turnserver --help", &out_str, &err_str, NULL, NULL) && err_str &&
      strstr (err_str, "--user") != NULL;

  g_free (err_str);
  g_free (out_str);

  return available;
}

static void
print_candidate (gpointer data, gpointer user_data)
{
  NiceCandidate *cand = data;
  gchar str_addr[INET6_ADDRSTRLEN];

  nice_address_to_string (&cand->addr, str_addr);

  g_debug (
      "  type=%s transport=%s %s:%u",
      nice_candidate_type_to_string (cand->type),
      nice_candidate_transport_to_string (cand->transport),
      str_addr,
      nice_address_get_port (&cand->addr));
}

void
test_common_set_candidates (
    NiceAgent *from,
    guint from_stream,
    NiceAgent *to,
    guint to_stream,
    guint component,
    gboolean remove_non_relay,
    gboolean force_relay)
{
  GSList *cands = NULL, *i;

  cands = nice_agent_get_local_candidates (from, from_stream, component);
  g_debug ("Potential candidates from agent %p", from);
  g_slist_foreach (cands, print_candidate, NULL);
  if (remove_non_relay) {
  restart:
    for (i = cands; i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (force_relay)
        g_assert_cmpint (cand->type, ==, NICE_CANDIDATE_TYPE_RELAYED);
      if (cand->type != NICE_CANDIDATE_TYPE_RELAYED) {
        cands = g_slist_remove (cands, cand);
        nice_candidate_free (cand);
        goto restart;
      }
    }
  }

  // Without any remaining candidates all hope is lost so fail early if so.
  g_assert (g_slist_length (cands) > 0);

  g_debug ("Actually set candidates from agent %p to agent %p", from, to);
  g_slist_foreach (cands, print_candidate, NULL);
  nice_agent_set_remote_candidates (to, to_stream, component, cands);

  for (i = cands; i; i = i->next)
    nice_candidate_free ((NiceCandidate *) i->data);
  g_slist_free (cands);
}
