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

#include <gst/gst.h>

#include <nice/nice.h>

#include "stun.h"

#include "gstnice.h"

static GMainLoop *loop = NULL;

/* XXX: code duplicated from agent/test-send.c */
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
      g_assert (candidates);
      local = candidates->data;
      g_assert (local->id == 1);
      g_slist_free (candidates);
    }

    {
      GSList *candidates;

      candidates = nice_agent_get_remote_candidates (agent, 1, 1);
      g_assert (candidates);
      remote = candidates->data;
      g_slist_free (candidates);
    }

  sock = &local->sock;

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
    NiceAddress addr = {0,};
    gchar packed[1024];
    gchar *dump;
    guint len;

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
    NiceAddress addr = {0,};
    gchar packed[1024];
    gchar *dump;
    guint len;

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

static gboolean
recv_cb (
  GIOChannel *source,
  GIOCondition condition,
  gpointer data)
{
  /* return value is whether to keep the source */

  NiceAgent *agent = data;
  NiceCandidate *candidate;
  NiceUDPSocket *sock;
  NiceAddress from;
  guint len;
  gchar buf[1024];

    {
      GSList *candidates;

      candidates = nice_agent_get_local_candidates (agent, 1, 1);
      g_assert (candidates);
      candidate = candidates->data;
      g_slist_free (candidates);
    }

  sock = &candidate->sock;
  len = nice_udp_fake_socket_pop_send (
      sock, &from, 1024, buf);

  g_assert (len == 6);
  g_assert (0 == strncmp (buf, "\x80hello", len));

  g_main_loop_quit (loop);
  return FALSE;
}

int
main (gint argc, gchar *argv[])
{
  GstElement *src;
  GstElement *sink;
  GstElement *pipeline;
  NiceAgent *agent;
  NiceAddress addr = {0,};
  NiceUDPSocketFactory factory;

  gst_init (&argc, &argv);

  nice_rng_set_new_func (nice_rng_glib_new_predictable);

  // set up agent

  nice_address_set_ipv4 (&addr, 0x7f000001);
  nice_udp_fake_socket_factory_init (&factory);
  agent = nice_agent_new (&factory);
  nice_agent_add_local_address (agent, &addr);
  nice_address_set_ipv4 (&addr, 0xc0a80002);
  addr.port = 2345;
  nice_agent_add_stream (agent, 1);
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &addr, "username", "password");

  // send connectivity check so that sending works

  send_connectivity_check (agent, &addr);

    {
      GIOChannel *io;
      GSource *source;
      NiceCandidate *candidate;
      NiceUDPSocket *sock;
      GSList *candidates;

      candidates = nice_agent_get_local_candidates (agent, 1, 1);
      g_assert (candidates);
      candidate = candidates->data;
      sock = &candidate->sock;
      g_slist_free (candidates);

      // send test packet

      nice_udp_fake_socket_push_recv (sock, &addr, 6, "\x80hello");

      // watch socket for reveived data

      io = g_io_channel_unix_new (nice_udp_fake_socket_get_peer_fd (sock));
      source = g_io_create_watch (io, G_IO_IN);
      g_source_set_callback (source, (GSourceFunc) recv_cb,
          agent, NULL);
      g_source_attach (source, NULL);
    }

  // set up pipeline

  src = g_object_new (GST_TYPE_NICE_SRC,
      "agent", agent,
      "stream", 1,
      "component", 1,
      NULL);

  sink = g_object_new (GST_TYPE_NICE_SINK,
      "agent", agent,
      "stream", 1,
      "component", 1,
      NULL);

  pipeline = gst_pipeline_new (NULL);
  gst_bin_add (GST_BIN (pipeline), src);
  gst_bin_add (GST_BIN (pipeline), sink);
  g_assert (gst_element_link (src, sink));
  gst_element_set_state (pipeline, GST_STATE_PLAYING);

  // loop

  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);
  g_main_loop_unref (loop);

  // clean up

  gst_object_unref (pipeline);
  g_object_unref (agent);
  nice_udp_socket_factory_close (&factory);
  gst_deinit ();
  return 0;
}

