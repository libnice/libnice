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

#include "stun.h"
#include "udp-fake.h"
#include "agent.h"

static void
test_stun_no_password (
  NiceAgent *agent,
  NiceAddress from,
  NiceUDPSocket *sock)
{
  NiceAddress to;
  guint len;
  gchar buf[1024];
  guint packed_len;
  gchar *packed;

  memset (&to, 0, sizeof (to));
  memset (buf, '\0', 1024);

    {
      StunMessage *breq;

      /* send binding request without username */
      breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (breq, &packed);
      nice_udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

  /* tell the agent there's a packet waiting */
  nice_agent_poll_read (agent, NULL, NULL, NULL);

  /* error response should have been sent */
  len = nice_udp_fake_socket_pop_send (sock, &to,
      sizeof (buf) / sizeof (gchar), buf);
  g_assert (len != 0);

    {
      StunMessage *bres;

      /* construct expected response */
      bres = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (bres, &packed);

      stun_message_free (bres);
    }

  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_free (packed);
}

static void
test_stun_invalid_password (
  NiceAgent *agent,
  NiceAddress from,
  NiceUDPSocket *sock)
{
  NiceAddress to;
  guint len;
  gchar buf[1024];
  guint packed_len;
  gchar *packed;

  memset (&to, 0, sizeof (to));
  memset (buf, '\0', 1024);

    {
      StunMessage *breq;

      /* send binding request with incorrect username */
      breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          "0123456789abcdef", 1);
      breq->attributes[0] = stun_attribute_username_new ("lala");
      packed_len = stun_message_pack (breq, &packed);
      g_assert (packed_len != 0);
      nice_udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

  /* tell the agent there's a packet waiting */
  nice_agent_poll_read (agent, NULL, NULL, NULL);

  /* error should have been sent */
  len = nice_udp_fake_socket_pop_send (sock, &to,
      sizeof (buf) / sizeof (gchar), buf);
  g_assert (len != 0);

    {
      StunMessage *bres;

      /* construct expected response */
      bres = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (bres, &packed);
      stun_message_free (bres);
    }

  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_free (packed);
}

static void
test_stun_valid_password (
  NiceAgent *agent,
  NiceAddress from,
  NiceCandidate *candidate,
  NiceUDPSocket *sock)
{
  NiceAddress to;
  guint len;
  guint packed_len;
  gchar buf[1024];
  gchar *packed;
  gchar *username;

  memset (&to, 0, sizeof (to));
  memset (buf, '\0', 1024);

  username = g_strconcat (candidate->username, "username", NULL);

    {
      StunMessage *breq;
      guint packed_len;
      gchar *packed;

      /* send binding request with correct username */
      breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          "0123456789abcdef", 1);
      breq->attributes[0] = stun_attribute_username_new (username);
      packed_len = stun_message_pack (breq, &packed);
      g_assert (packed_len != 0);
      nice_udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

    {
      StunMessage *bres;

      /* construct expected response packet */
      bres = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE,
          "0123456789abcdef", 2);
      bres->attributes[0] = stun_attribute_mapped_address_new (
          from.addr.addr_ipv4, 5678);
      bres->attributes[1] = stun_attribute_username_new (username);
      packed_len = stun_message_pack (bres, &packed);
      stun_message_free (bres);
    }

  g_free (username);

  /* tell the agent there's a packet waiting */
  nice_agent_poll_read (agent, NULL, NULL, NULL);

  /* compare sent packet to expected */
  len = nice_udp_fake_socket_pop_send (sock, &to,
      sizeof (buf) / sizeof (gchar), buf);
  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_assert (nice_address_equal (&to, &from));
  g_free (packed);
}

int
main (void)
{
  NiceAgent *agent;
  NiceAddress local_addr;
  NiceAddress remote_addr;
  NiceCandidate *candidate;
  NiceUDPSocketFactory factory;
  NiceUDPSocket *sock;
  GSList *candidates;

  memset (&local_addr, 0, sizeof (local_addr));
  memset (&remote_addr, 0, sizeof (remote_addr));
  g_type_init ();

  nice_udp_fake_socket_factory_init (&factory);

  g_assert (nice_address_set_ipv4_from_string (&local_addr, "192.168.0.1"));
  g_assert (nice_address_set_ipv4_from_string (&remote_addr, "192.168.0.5"));
  remote_addr.port = 5678;

  /* set up agent */
  agent = nice_agent_new (&factory);
  nice_agent_add_local_address (agent, &local_addr);
  nice_agent_add_stream (agent, 1);
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &remote_addr, "username", "password");

  candidates = nice_agent_get_local_candidates (agent, 1, 1);
  candidate = candidates->data;
  sock = candidate->sockptr;
  g_slist_free (candidates);

  /* run tests */
  test_stun_no_password (agent, remote_addr, sock);
  test_stun_invalid_password (agent, remote_addr, sock);
  test_stun_valid_password (agent, remote_addr, candidate, sock);

  /* clean up */
  g_object_unref (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

