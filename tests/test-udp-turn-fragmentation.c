/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2018 Jakub Adam <jakub.adam@ktknet.cz>
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

#include <gio/gnetworking.h>

#include "agent-priv.h"
#include "socket.h"

static GRand *randg;

static GSList *
generate_test_messages(void)
{
  guint i;
  GSList *result = NULL;

  for (i = 0; i != 100; ++i) {
    GInputVector *msg_data = g_new (GInputVector, 1);
    gsize msg_size = g_rand_int_range (randg, 0, G_MAXUINT16);
    gsize j;

    msg_data->size = msg_size + sizeof (guint16);
    msg_data->buffer = g_malloc (msg_data->size);
    *(guint16 *)(msg_data->buffer) = htons (msg_size);

    for (j = 2; j != msg_data->size; ++j) {
      ((guint8 *)msg_data->buffer)[j] = g_rand_int(randg);
    }

    result = g_slist_append(result, msg_data);
  }

  return result;
}

typedef struct {
  GSList *msg_data;
  GSList *current_msg;
  gsize offset;
  guint8 send_buffer[G_MAXUINT16 + sizeof (guint16)];
} TestSocketPriv;

static gint
test_socket_recv_messages (NiceSocket *sock, NiceInputMessage *recv_messages,
    guint n_recv_messages) {
  TestSocketPriv *priv = sock->priv;
  guint i;

  for (i = 0; priv->current_msg && i != n_recv_messages; ++i) {
    gsize msg_size = g_rand_int_range (randg, 0, G_MAXUINT16) + sizeof (guint16);
    gsize j;

    j = sizeof (guint16);
    while (priv->current_msg && j < msg_size) {
      GInputVector *msg = priv->current_msg->data;
      gsize cpylen = MIN (msg->size - priv->offset, msg_size - j);
      memcpy (priv->send_buffer + j, (guint8 *)msg->buffer + priv->offset,
          cpylen);
      priv->offset += cpylen;
      j += cpylen;

      if (priv->offset == msg->size) {
        priv->current_msg = priv->current_msg->next;
        priv->offset = 0;
      }
    }

    msg_size = j;
    *(guint16 *)(priv->send_buffer) = htons (msg_size - sizeof (guint16));

    memcpy_buffer_to_input_message (&recv_messages[i], priv->send_buffer, msg_size);
    nice_address_set_from_string (recv_messages[i].from, "127.0.0.1");
  }

  return i;
}

static gboolean
test_socket_is_reliable (NiceSocket *sock) {
  return TRUE;
}

static void
test_socket_close (NiceSocket *sock) {
  g_free (sock->priv);
}

static NiceSocket *
test_socket_new (GSList *msg_data)
{
  NiceSocket *sock = g_slice_new0 (NiceSocket);
  TestSocketPriv *priv = g_new0 (TestSocketPriv, 1);
  priv->msg_data = msg_data;
  priv->current_msg = msg_data;
  priv->offset = 0;

  sock->type = NICE_SOCKET_TYPE_UDP_TURN_OVER_TCP;
  sock->recv_messages = test_socket_recv_messages;
  sock->is_reliable = test_socket_is_reliable;
  sock->close = test_socket_close;
  sock->priv = (void *) priv;

  return sock;
}

#define N_RECV_MESSAGES 7

static void
tcp_turn_fragmentation (void)
{
  /* Generate some RFC4571-framed test messages. A dummy base socket will split
   * them randomly into TCP-TURN messages. Test that tcp-turn socket can
   * correctly extract and reassemble the original test data out of the TURN
   * messages. */
  GSList *test_messages = generate_test_messages ();
  NiceAddress addr;
  NiceSocket *turnsock;
  NiceSocket *testsock;

  NiceInputMessage recv_messages[N_RECV_MESSAGES];
  GInputVector recv_vectors[N_RECV_MESSAGES];
  NiceAddress recv_addr[N_RECV_MESSAGES];
  guint8 recv_buffers[N_RECV_MESSAGES][G_MAXUINT16 + sizeof (guint16)];

  gint n_messages;
  guint i;
  GSList *li;

  for (i = 0; i != N_RECV_MESSAGES; ++i) {
    recv_messages[i].buffers = &recv_vectors[i];
    recv_messages[i].from = &recv_addr[i];
    recv_messages[i].n_buffers = 1;
    recv_messages[i].length = 0;
    recv_vectors[i].buffer = &recv_buffers[i];
    recv_vectors[i].size = sizeof (recv_buffers[i]);
  }

  nice_address_set_from_string (&addr, "127.0.0.1");

  testsock = test_socket_new (test_messages);

  turnsock = nice_udp_turn_socket_new (NULL, &addr,
      testsock, &addr, "", "",
      NICE_TURN_SOCKET_COMPATIBILITY_OC2007);

  li = test_messages;
  while (li) {
    n_messages = nice_socket_recv_messages (turnsock, recv_messages,
        N_RECV_MESSAGES);

    for (i = 0; i != (guint)n_messages; ++i) {
      NiceInputMessage *message = &recv_messages[i];
      GInputVector *vec = li->data;
      if (message->length == 0) {
        continue;
      }
      g_assert (message->length == vec->size);
      g_assert (!memcmp (message->buffers->buffer, vec->buffer,
          message->length));

      li = li->next;
    }
  }

  for (li = test_messages; li; li = li->next) {
    GInputVector *v = li->data;
    g_free (v->buffer);
    g_free (v);
  }
  g_slist_free (test_messages);

  nice_socket_free (turnsock);
  nice_socket_free (testsock);
}

int
main (int argc, char *argv[])
{
  GMainLoop *mainloop;

  g_networking_init ();

  randg = g_rand_new();
  g_test_init (&argc, &argv, NULL);

  mainloop = g_main_loop_new (NULL, TRUE);

  g_test_add_func ("/udp-turn/tcp-fragmentation", tcp_turn_fragmentation);

  g_test_run ();

  g_rand_free(randg);

  g_main_loop_unref (mainloop);

  return 0;
}
