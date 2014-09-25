/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007, 2014 Collabora Ltd.
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
 *   Philip Withnall, Collabora Ltd.
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

#include "socket.h"

static gssize
socket_recv (NiceSocket *sock, NiceAddress *addr, gsize buf_len, gchar *buf)
{
  GInputVector local_buf = { buf, buf_len };
  NiceInputMessage local_message = { &local_buf, 1, addr, 0 };
  gint ret;

  ret = nice_socket_recv_messages (sock, &local_message, 1);
  if (ret <= 0)
    return ret;

  return local_buf.size;
}

static void
test_socket_initial_properties (void)
{
  NiceSocket *sock;

  sock = nice_udp_bsd_socket_new (NULL);
  g_assert (sock != NULL);

  // not bound to a particular interface
  g_assert_cmpint (sock->addr.s.ip4.sin_addr.s_addr, ==, 0);
  // is bound to a particular port
  g_assert_cmpuint (nice_address_get_port (&sock->addr), !=, 0);

  nice_socket_free (sock);
}

static void
test_socket_address_properties (void)
{
  NiceSocket *sock;
  NiceAddress tmp;

  sock = nice_udp_bsd_socket_new (NULL);
  g_assert (sock != NULL);

  g_assert (nice_address_set_from_string (&tmp, "127.0.0.1"));
  g_assert_cmpuint (nice_address_get_port (&sock->addr), !=, 0);
  nice_address_set_port (&tmp, nice_address_get_port (&sock->addr));
  g_assert_cmpuint (nice_address_get_port (&tmp), !=, 0);

  nice_socket_free (sock);
}

static void
test_simple_send_recv (void)
{
  NiceSocket *server;
  NiceSocket *client;
  NiceAddress tmp;
  gchar buf[5];

  server = nice_udp_bsd_socket_new (NULL);
  g_assert (server != NULL);

  client = nice_udp_bsd_socket_new (NULL);
  g_assert (client != NULL);

  g_assert (nice_address_set_from_string (&tmp, "127.0.0.1"));
  nice_address_set_port (&tmp, nice_address_get_port (&server->addr));

  /* Send and receive stuff. */
  g_assert_cmpint (nice_socket_send (client, &tmp, 5, "hello"), ==, 5);

  g_assert_cmpint (socket_recv (server, &tmp, 5, buf), ==, 5);
  g_assert_cmpint (strncmp (buf, "hello", 5), ==, 0);

  g_assert_cmpint (nice_socket_send (server, &tmp, 5, "uryyb"), ==, 5);

  g_assert_cmpint (socket_recv (client, &tmp, 5, buf), ==, 5);
  g_assert_cmpint (strncmp (buf, "uryyb", 5), ==, 0);

  nice_socket_free (client);
  nice_socket_free (server);
}

/* Check that sending and receiving to/from zero-length buffers returns
 * immediately. */
static void
test_zero_send_recv (void)
{
  NiceSocket *sock;
  NiceAddress tmp;
  gchar buf[5];
  NiceOutputMessage local_out_message;
  NiceInputMessage local_in_message;

  sock = nice_udp_bsd_socket_new (NULL);
  g_assert (sock != NULL);

  g_assert (nice_address_set_from_string (&tmp, "127.0.0.1"));
  g_assert_cmpuint (nice_address_get_port (&sock->addr), !=, 0);
  nice_address_set_port (&tmp, nice_address_get_port (&sock->addr));
  g_assert_cmpuint (nice_address_get_port (&tmp), !=, 0);

  g_assert_cmpint (nice_socket_send (sock, &tmp, 0, "ignore-me"), ==, 0);
  g_assert_cmpint (nice_socket_send (sock, &tmp, 0, NULL), ==, 0);

  g_assert_cmpint (socket_recv (sock, &tmp, 0, buf), ==, 0);
  g_assert_cmpint (socket_recv (sock, &tmp, 0, NULL), ==, 0);

  /* And again with messages. */
  g_assert_cmpint (nice_socket_send_messages (sock, &tmp,
      &local_out_message, 0), ==, 0);
  g_assert_cmpint (nice_socket_send_messages (sock, &tmp, NULL, 0), ==, 0);

  g_assert_cmpint (nice_socket_recv_messages (sock,
      &local_in_message, 0), ==, 0);
  g_assert_cmpint (nice_socket_recv_messages (sock, NULL, 0), ==, 0);

  nice_socket_free (sock);
}

/* Test receiving into multiple tiny buffers. */
static void
test_multi_buffer_recv (void)
{
  NiceSocket *server;
  NiceSocket *client;
  NiceAddress tmp;
  guint8 buf[20];
  guint8 dummy_buf[9];

  server = nice_udp_bsd_socket_new (NULL);
  g_assert (server != NULL);

  client = nice_udp_bsd_socket_new (NULL);
  g_assert (client != NULL);

  g_assert (nice_address_set_from_string (&tmp, "127.0.0.1"));
  nice_address_set_port (&tmp, nice_address_get_port (&server->addr));

  /* Send and receive stuff. */
  {
    GInputVector bufs[7] = {
      { &buf[0], 1 },
      { &buf[1], 4 },
      { &buf[1], 0 },  /* should be unused (zero-length) */
      { &buf[5], 1 },
      { &buf[6], 5 },
      { &buf[11], 9 },  /* should be unused (message fits in prior buffers) */
      { &buf[11], 0 },  /* should be unused (zero-length) */
    };
    NiceInputMessage message = { bufs, G_N_ELEMENTS (bufs), NULL, 0 };

    /* Initialise the buffers so we can try and catch out-of-bounds accesses. */
    memset (buf, 0xaa, sizeof (buf));
    memset (dummy_buf, 0xaa, sizeof (dummy_buf));

    /* Send and receive. */
    g_assert_cmpint (nice_socket_send (client, &tmp, 11, "hello-world"), ==, 11);
    g_assert_cmpuint (nice_socket_recv_messages (server, &message, 1), ==, 1);
    g_assert_cmpuint (message.length, ==, 11);

    /* Check all of the things. The sizes should not have been modified. */
    g_assert_cmpuint (bufs[0].size, ==, 1);
    g_assert_cmpuint (bufs[1].size, ==, 4);
    g_assert_cmpuint (bufs[2].size, ==, 0);
    g_assert_cmpuint (bufs[3].size, ==, 1);
    g_assert_cmpuint (bufs[4].size, ==, 5);
    g_assert_cmpuint (bufs[5].size, ==, 9);
    g_assert_cmpuint (bufs[6].size, ==, 0);

    g_assert_cmpint (strncmp ((gchar *) buf, "hello-world", 11), ==, 0);
    g_assert_cmpint (memcmp (buf + 11, dummy_buf, 9), ==, 0);
  }

  nice_socket_free (client);
  nice_socket_free (server);
}

/* Fill a buffer with deterministic but non-repeated data, so that transmission
 * and reception corruption is more likely to be detected. */
static void
fill_send_buf (guint8 *buf, gsize buf_len, guint seed)
{
  gsize i;

  for (i = 0; i < buf_len; i++) {
    buf[i] = '0' + (seed % 10);
    seed++;
  }
}

/* Test receiving multiple messages in a single call. */
static void
test_multi_message_recv (guint n_sends, guint n_receives,
    guint n_bufs_per_message, gsize send_buf_size, gsize recv_buf_size,
    guint expected_n_received_messages, guint expected_n_sent_messages)
{
  NiceSocket *server;
  NiceSocket *client;
  NiceAddress tmp;

  server = nice_udp_bsd_socket_new (NULL);
  g_assert (server != NULL);

  client = nice_udp_bsd_socket_new (NULL);
  g_assert (client != NULL);

  g_assert (nice_address_set_from_string (&tmp, "127.0.0.1"));
  nice_address_set_port (&tmp, nice_address_get_port (&server->addr));

  /* Send and receive stuff. */
  {
    GInputVector *recv_bufs;
    NiceInputMessage *recv_messages;
    GOutputVector *send_bufs;
    NiceOutputMessage *send_messages;
    guint i, j;
    guint8 *_expected_recv_buf;
    gsize expected_recv_buf_len;

    /* Set up the send buffers. */
    send_bufs = g_malloc0_n (n_sends * n_bufs_per_message,
        sizeof (GOutputVector));
    send_messages = g_malloc0_n (n_sends, sizeof (NiceOutputMessage));

    for (i = 0; i < n_sends; i++) {
      for (j = 0; j < n_bufs_per_message; j++) {
        guint8 *buf = g_slice_alloc (send_buf_size);

        send_bufs[i * n_bufs_per_message + j].buffer = buf;
        send_bufs[i * n_bufs_per_message + j].size = send_buf_size;

        /* Set up the buffer data. */
        fill_send_buf (buf, send_buf_size, i);
      }

      send_messages[i].buffers = send_bufs + i * n_bufs_per_message;
      send_messages[i].n_buffers = n_bufs_per_message;
    }

    /* Set up the receive buffers. Yay for dynamic tests! */
    recv_bufs = g_malloc0_n (n_receives * n_bufs_per_message,
        sizeof (GInputVector));
    recv_messages = g_malloc0_n (n_receives, sizeof (NiceInputMessage));

    for (i = 0; i < n_receives; i++) {
      for (j = 0; j < n_bufs_per_message; j++) {
        recv_bufs[i * n_bufs_per_message + j].buffer =
            g_slice_alloc (recv_buf_size);
        recv_bufs[i * n_bufs_per_message + j].size = recv_buf_size;

        /* Initialise the buffer to try to catch out-of-bounds accesses. */
        memset (recv_bufs[i * n_bufs_per_message + j].buffer, 0xaa,
            recv_buf_size);
      }

      recv_messages[i].buffers = recv_bufs + i * n_bufs_per_message;
      recv_messages[i].n_buffers = n_bufs_per_message;
      recv_messages[i].from = NULL;
      recv_messages[i].length = 0;
    }

    /* Send multiple packets. */
    g_assert_cmpint (
        nice_socket_send_messages (client, &tmp, send_messages, n_sends), ==,
        expected_n_sent_messages);

    /* Receive things. */
    g_assert_cmpint (
        nice_socket_recv_messages (server, recv_messages, n_receives), ==,
        expected_n_received_messages);

    /* Check all of the things. The sizes should not have been modified. */
    expected_recv_buf_len = recv_buf_size * n_bufs_per_message;
    _expected_recv_buf = g_slice_alloc (expected_recv_buf_len);

    for (i = 0; i < expected_n_received_messages; i++) {
      NiceInputMessage *message = &recv_messages[i];
      guint8 *expected_recv_buf = _expected_recv_buf;
      gsize expected_len;

      expected_len = MIN (send_buf_size * n_bufs_per_message,
          expected_recv_buf_len);
      g_assert_cmpuint (message->length, ==, expected_len);

      /* Build the expected buffer as a concatenation of the expected values of
       * all receive buffers in the message. */
      memset (expected_recv_buf, 0xaa, expected_recv_buf_len);
      fill_send_buf (expected_recv_buf, expected_len, i);

      for (j = 0; j < n_bufs_per_message; j++) {
        g_assert_cmpuint (message->buffers[j].size, ==, recv_buf_size);
        g_assert_cmpint (
            memcmp (message->buffers[j].buffer, expected_recv_buf,
                recv_buf_size), ==, 0);

        expected_recv_buf += recv_buf_size;
      }
    }

    g_slice_free1 (expected_recv_buf_len, _expected_recv_buf);

    for (i = 0; i < n_receives; i++) {
      for (j = 0; j < n_bufs_per_message; j++) {
        g_slice_free1 (recv_buf_size,
                       recv_bufs[i * n_bufs_per_message + j].buffer);
      }
    }

    for (i = 0; i < n_sends; i++) {
      for (j = 0; j < n_bufs_per_message; j++) {
        g_slice_free1 (send_buf_size,
                       (gpointer) send_bufs[i * n_bufs_per_message + j].buffer);
      }
    }

    g_free (recv_messages);
    g_free (recv_bufs);
    g_free (send_messages);
    g_free (send_bufs);
  }

  nice_socket_free (client);
  nice_socket_free (server);
}

int
main (void)
{
  g_type_init ();

  test_socket_initial_properties ();
  test_socket_address_properties ();
  test_simple_send_recv ();
  test_zero_send_recv ();
  test_multi_buffer_recv ();

  /* Multi-message testing. Serious business. */
  {
    guint i;
    struct {
      guint n_sends;  /* messages */
      guint expected_n_sent_messages;

      guint n_receives;  /* messages */
      guint expected_n_received_messages;

      guint n_bufs_per_message;
      gsize send_buf_size;
      gsize recv_buf_size;
    } test_cases[] = {
      /* same number of sends and receives */
      {   2,   2,   2,   2,   1, 100, 100 },  /* send 200B, receive 200B */
      /* more sends than receives */
      {   4,   4,   2,   2,   2, 100,  77 },  /* send 800B, receive 308B */
      /* more receives than sends */
      {   1,   1,   4,   1,   4,  10, 100 },  /* send 40B, receive 1600B */
      /* small receive buffer (data loss) */
      { 100, 100, 100, 100,   1, 100,  64 },  /* send 10000B, receive 6400B */
      /* small receive buffers (data loss) */
      {  50,  50,  50,  50,  10, 100,   8 },  /* send 50000B, receive 4000B */
    };

    for (i = 0; i < G_N_ELEMENTS (test_cases); i++) {
      test_multi_message_recv (test_cases[i].n_sends, test_cases[i].n_receives,
          test_cases[i].n_bufs_per_message, test_cases[i].send_buf_size,
          test_cases[i].recv_buf_size,
          test_cases[i].expected_n_received_messages,
          test_cases[i].expected_n_sent_messages);
    }
  }

  return 0;
}

