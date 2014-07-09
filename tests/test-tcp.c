/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2012 Collabora Ltd.
 *  Contact: George Kiagiadakis
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
 *   George Kiagiadakis, Collabora Ltd.
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

#include "socket.h"

GMainLoop *mainloop = NULL;
NiceSocket *active_sock, *client;
NiceSocket *passive_sock, *server;
NiceAddress tmp;
gchar buf[5];

static gboolean
on_server_connection_available (gpointer user_data)
{
  server = nice_tcp_passive_socket_accept (passive_sock);
  g_assert (server);
  nice_socket_free (passive_sock);
  passive_sock = NULL;

  g_main_loop_quit (mainloop);

  return FALSE;
}

static gboolean
on_server_input_available (gpointer user_data)
{
  g_assert (5 == nice_socket_recv (server, &tmp, 5, buf));
  g_assert (nice_address_equal (&tmp, &client->addr));

  g_main_loop_quit (mainloop);

  return FALSE;
}

static gboolean
on_client_input_available (gpointer user_data)
{
  g_assert (5 == nice_socket_recv (client, &tmp, 5, buf));
  g_assert (nice_address_equal (&tmp, &server->addr));

  g_main_loop_quit (mainloop);

  return FALSE;
}

int
main (void)
{
  NiceAddress active_bind_addr, passive_bind_addr;
  GSource *srv_listen_source, *srv_input_source, *cli_input_source;

  g_type_init ();

  mainloop = g_main_loop_new (NULL, FALSE);

  nice_address_init (&active_bind_addr);
  g_assert (nice_address_set_from_string (&active_bind_addr, "::1"));

  nice_address_init (&passive_bind_addr);
  g_assert (nice_address_set_from_string (&passive_bind_addr, "::1"));
  nice_address_set_port (&passive_bind_addr, 23456);

  nice_address_init (&tmp);

  passive_sock = nice_tcp_passive_socket_new (g_main_loop_get_context (mainloop),
      &passive_bind_addr);
  g_assert (passive_sock);

  srv_listen_source = g_socket_create_source (passive_sock->fileno,
      G_IO_IN, NULL);
  g_source_set_callback (srv_listen_source,
      on_server_connection_available, NULL, NULL);
  g_source_attach (srv_listen_source, g_main_loop_get_context (mainloop));

  active_sock = nice_tcp_active_socket_new (g_main_loop_get_context (mainloop),
      &active_bind_addr);
  g_assert (active_sock);

  client = nice_tcp_active_socket_connect (active_sock, &passive_bind_addr);
  g_assert (client);
  nice_socket_free (active_sock);
  active_sock = NULL;

  g_main_loop_run (mainloop); /* -> on_server_connection_available */
  g_assert (server);

  srv_input_source = g_socket_create_source (server->fileno, G_IO_IN, NULL);
  g_source_set_callback (srv_input_source,
      on_server_input_available, NULL, NULL);
  g_source_attach (srv_input_source, g_main_loop_get_context (mainloop));

  cli_input_source = g_socket_create_source (client->fileno, G_IO_IN, NULL);
  g_source_set_callback (cli_input_source,
      on_client_input_available, NULL, NULL);
  g_source_attach (cli_input_source, g_main_loop_get_context (mainloop));

  g_assert (nice_address_get_port (&client->addr) != 0);
  g_assert (nice_address_get_port (&server->addr) == 23456);

  g_assert (nice_address_set_from_string (&tmp, "::1"));
  nice_address_set_port (&tmp, nice_address_get_port (&server->addr));
  g_assert (nice_address_get_port (&tmp) != 0);


  g_assert (5 == nice_socket_send (client, &tmp, 5, "hello"));
  g_main_loop_run (mainloop); /* -> on_server_input_available */
  g_assert (0 == strncmp (buf, "hello", 5));

  g_assert (5 == nice_socket_send (server, &tmp, 5, "uryyb"));
  g_main_loop_run (mainloop); /* -> on_client_input_available */
  g_assert (0 == strncmp (buf, "uryyb", 5));

  nice_socket_free (client);
  nice_socket_free (server);

  g_source_unref (srv_listen_source);
  g_source_unref (srv_input_source);
  g_source_unref (cli_input_source);
  g_main_loop_unref (mainloop);

  return 0;
}
