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
