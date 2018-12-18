/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2016 Jakub Adam <jakub.adam@ktknet.cz>
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

#include <locale.h>
#include <gio/gnetworking.h>

#include "socket.h"

static NiceSocket *udp_bsd;
static NiceSocket *tcp_active;
static NiceSocket *pseudossl;
static NiceSocket *udp_turn_over_tcp;

static void
socket_base_udp_bsd (void)
{
  g_assert (nice_socket_is_based_on (udp_bsd, udp_bsd));
  g_assert (!nice_socket_is_based_on (udp_bsd, tcp_active));
  g_assert (!nice_socket_is_based_on (udp_bsd, pseudossl));
  g_assert (!nice_socket_is_based_on (udp_bsd, udp_turn_over_tcp));
}

static void
socket_base_tcp_active (void)
{
  g_assert (!nice_socket_is_based_on (tcp_active, udp_bsd));
  g_assert (nice_socket_is_based_on (tcp_active, tcp_active));
  g_assert (!nice_socket_is_based_on (tcp_active, pseudossl));
  g_assert (!nice_socket_is_based_on (tcp_active, udp_turn_over_tcp));
}

static void
socket_base_pseudossl (void)
{
  g_assert (!nice_socket_is_based_on (pseudossl, udp_bsd));
  g_assert (nice_socket_is_based_on (pseudossl, tcp_active));
  g_assert (nice_socket_is_based_on (pseudossl, pseudossl));
  g_assert (!nice_socket_is_based_on (pseudossl, udp_turn_over_tcp));
}

static void
socket_base_udp_turn_over_tcp (void)
{
  g_assert (!nice_socket_is_based_on (udp_turn_over_tcp, udp_bsd));
  g_assert (nice_socket_is_based_on (udp_turn_over_tcp, tcp_active));
  g_assert (nice_socket_is_based_on (udp_turn_over_tcp, pseudossl));
  g_assert (nice_socket_is_based_on (udp_turn_over_tcp, udp_turn_over_tcp));
}

int
main (int argc, char *argv[])
{
  GMainLoop *mainloop = NULL;

  NiceAddress addr;

  g_networking_init ();

  setlocale (LC_ALL, "");
  g_test_init (&argc, &argv, NULL);

  mainloop = g_main_loop_new (NULL, TRUE);

  nice_address_set_from_string (&addr, "127.0.0.1");

  /* Standalone socket */
  udp_bsd = nice_udp_bsd_socket_new (&addr);

  /* tcp_passive -> pseudossl -> udp_turn_over_tcp */
  tcp_active = nice_tcp_active_socket_new (g_main_loop_get_context (mainloop),
      &addr);
  pseudossl = nice_pseudossl_socket_new (tcp_active,
      NICE_PSEUDOSSL_SOCKET_COMPATIBILITY_GOOGLE);
  udp_turn_over_tcp = nice_udp_turn_over_tcp_socket_new (pseudossl,
      NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE);

  g_test_add_func ("/socket/is-base-of/udp-bsd",
      socket_base_udp_bsd);
  g_test_add_func ("/socket/is-base-of/tcp-active",
      socket_base_tcp_active);
  g_test_add_func ("/socket/is-base-of/pseudossl",
      socket_base_pseudossl);
  g_test_add_func ("/socket/is-base-of/udp-turn-over-tcp",
      socket_base_udp_turn_over_tcp);

  g_test_run ();

  nice_socket_free (udp_bsd);
  nice_socket_free (udp_turn_over_tcp);

  g_main_loop_unref (mainloop);

  return 0;
}
