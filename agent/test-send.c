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

#include <sys/select.h>

#include "agent.h"
#include "stun.h"
#include "udp-fake.h"
#include "random-glib.h"

static gboolean cb_called = FALSE;

static void
cb_component_state_changed (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint state)
{
  g_assert (agent != NULL);
  g_assert (stream_id == 1);
  g_assert (component_id == 1);
  g_assert (state == NICE_COMPONENT_STATE_CONNECTED);
  g_assert (cb_called == FALSE);
  cb_called = TRUE;
}


static gboolean
fd_is_readable (guint fd)
{
  fd_set fds;
  struct timeval timeout = { 0, 0 };

  FD_ZERO (&fds);
  FD_SET (fd, &fds);

  switch (select (fd + 1, &fds, NULL, NULL, &timeout))
    {
    case -1:
      g_assert_not_reached ();
    case 0:
      return FALSE;
    case 1:
      return TRUE;
    default:
      g_assert_not_reached ();
    }
}


static void
send_connectivity_check (
  NiceAgent *agent,
  NiceAddress *remote_addr)
{
  NiceUDPSocket *sock;
  NiceCandidate *local;
  NiceCandidate *remote;
  gchar *username;

  {
    GSList *candidates;

    candidates = nice_agent_get_local_candidates (agent, 1, 1);
    g_assert (g_slist_length (candidates) > 0);
    local = candidates->data;
    g_assert (strncmp (local->foundation, "1", 1) == 0);
    g_slist_free (candidates);
  }

  {
    GSList *candidates;

    candidates = nice_agent_get_remote_candidates (agent, 1, 1);
    g_assert (g_slist_length (candidates) > 0);
    remote = candidates->data;
    g_slist_free (candidates);
  }

  sock = local->sockptr;

  username = g_strconcat (local->username, remote->username, NULL);

  {
    StunMessage *msg;
    gchar *packed;
    guint len;

    msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST, NULL, 1);
    msg->attributes[0] = stun_attribute_username_new (username);
    len = stun_message_pack (msg, &packed);
    nice_udp_fake_socket_push_recv (sock, remote_addr, len, packed);
    g_free (packed);
    stun_message_free (msg);
  }

  nice_agent_poll_read (agent, NULL, NULL, NULL);

  {
    StunMessage *msg;
    NiceAddress addr;
    gchar packed[1024];
    gchar *dump;
    guint len;

    memset (&addr, 0, sizeof (addr));
    len = nice_udp_fake_socket_pop_send (sock, &addr, 1024, packed);
    g_assert (nice_address_equal (&addr, remote_addr));
    msg = stun_message_unpack (len, packed);
    dump = stun_message_dump (msg);
    g_assert (0 == strcmp (dump,
        "BINDING-RESPONSE 00000000:00000000:00000000:00000000\n"
        "  MAPPED-ADDRESS 192.168.0.2:2345\n"
        "  USERNAME \"S9PObXR5username\"\n"));
    g_free (dump);
    stun_message_free (msg);
  }

  {
    StunMessage *msg;
    NiceAddress addr;
    gchar packed[1024];
    gchar *dump;
    guint len;

    memset (&addr, 0, sizeof (addr));
    len = nice_udp_fake_socket_pop_send (sock, &addr, 1024, packed);
    g_assert (nice_address_equal (&addr, remote_addr));
    msg = stun_message_unpack (len, packed);
    dump = stun_message_dump (msg);
    g_assert (0 == strcmp (dump,
        "BINDING-REQUEST 588c3ac1:e62757ae:5851a519:4d480994\n"
        "  USERNAME \"usernameS9PObXR5\"\n"));
    g_free (dump);
    stun_message_free (msg);
  }

  g_free (username);
}


int
main (void)
{
  NiceUDPSocketFactory factory;
  NiceAgent *agent;
  NiceAddress local_addr;
  NiceAddress remote_addr;

  memset (&local_addr, 0, sizeof (local_addr));
  memset (&remote_addr, 0, sizeof (remote_addr));
  g_type_init ();

  /* set up */

  nice_rng_set_new_func (nice_rng_glib_new_predictable);

  nice_udp_fake_socket_factory_init (&factory);
  agent = nice_agent_new (&factory);

  if (!nice_address_set_ipv4_from_string (&local_addr, "192.168.0.1"))
    g_assert_not_reached ();

  nice_agent_add_local_address (agent, &local_addr);
  nice_agent_add_stream (agent, 1);

  if (!nice_address_set_ipv4_from_string (&remote_addr, "192.168.0.2"))
    g_assert_not_reached ();

  remote_addr.port = 2345;
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &remote_addr, "username", "password");

  g_signal_connect (agent, "component-state-changed",
      (GCallback) cb_component_state_changed, NULL);

  /* test */

  {
    NiceUDPSocket *sock;
    NiceAddress addr;
    gchar buf[1024];
    guint len;

      {
        GSList *candidates;
        NiceCandidate *candidate;

        candidates = nice_agent_get_local_candidates (agent, 1, 1);
        candidate = candidates->data;
        sock = candidate->sockptr;
        g_slist_free (candidates);
      }

    /* If we send data before we've received a connectivity check, we won't
     * have an affinity for any of the remote candidates, so the packet will
     * get silently dropped.
     */

    nice_agent_send (agent, 1, 1, 5, "hello");
    g_assert (0 == fd_is_readable (nice_udp_fake_socket_get_peer_fd (sock)));

    send_connectivity_check (agent, &remote_addr);

    /* Now that we've received a valid connectivity check, we have a local
     * socket to send from, and a remote address to send to.
     */

    nice_agent_send (agent, 1, 1, 5, "hello");
    len = nice_udp_fake_socket_pop_send (sock, &addr, 1024, buf);
    g_assert (len == 5);
    g_assert (0 == strncmp (buf, "hello", len));

    /* Signal to say component is connected should have been emitted. */

    g_assert (cb_called == TRUE);
  }

  /* clean up */

  g_object_unref (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

