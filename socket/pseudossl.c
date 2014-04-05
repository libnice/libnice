/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008-2009 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
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

/*
 * Implementation of TCP relay socket interface using TCP Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "pseudossl.h"
#include "agent-priv.h"

#include <string.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  gboolean handshaken;
  NiceSocket *base_socket;
  GQueue send_queue;
  NicePseudoSSLSocketCompatibility compatibility;
} PseudoSSLPriv;


struct to_be_sent {
  guint8 *buf;  /* owned */
  gsize length;
  NiceAddress to;
};


static const gchar SSL_SERVER_GOOGLE_HANDSHAKE[] = {
  0x16, 0x03, 0x01, 0x00, 0x4a, 0x02, 0x00, 0x00,
  0x46, 0x03, 0x01, 0x42, 0x85, 0x45, 0xa7, 0x27,
  0xa9, 0x5d, 0xa0, 0xb3, 0xc5, 0xe7, 0x53, 0xda,
  0x48, 0x2b, 0x3f, 0xc6, 0x5a, 0xca, 0x89, 0xc1,
  0x58, 0x52, 0xa1, 0x78, 0x3c, 0x5b, 0x17, 0x46,
  0x00, 0x85, 0x3f, 0x20, 0x0e, 0xd3, 0x06, 0x72,
  0x5b, 0x5b, 0x1b, 0x5f, 0x15, 0xac, 0x13, 0xf9,
  0x88, 0x53, 0x9d, 0x9b, 0xe8, 0x3d, 0x7b, 0x0c,
  0x30, 0x32, 0x6e, 0x38, 0x4d, 0xa2, 0x75, 0x57,
  0x41, 0x6c, 0x34, 0x5c, 0x00, 0x04, 0x00};

static const gchar SSL_CLIENT_GOOGLE_HANDSHAKE[] = {
  0x80, 0x46, 0x01, 0x03, 0x01, 0x00, 0x2d, 0x00,
  0x00, 0x00, 0x10, 0x01, 0x00, 0x80, 0x03, 0x00,
  0x80, 0x07, 0x00, 0xc0, 0x06, 0x00, 0x40, 0x02,
  0x00, 0x80, 0x04, 0x00, 0x80, 0x00, 0x00, 0x04,
  0x00, 0xfe, 0xff, 0x00, 0x00, 0x0a, 0x00, 0xfe,
  0xfe, 0x00, 0x00, 0x09, 0x00, 0x00, 0x64, 0x00,
  0x00, 0x62, 0x00, 0x00, 0x03, 0x00, 0x00, 0x06,
  0x1f, 0x17, 0x0c, 0xa6, 0x2f, 0x00, 0x78, 0xfc,
  0x46, 0x55, 0x2e, 0xb1, 0x83, 0x39, 0xf1, 0xea};

static const gchar SSL_SERVER_MSOC_HANDSHAKE[] = {
  0x16, 0x03, 0x01, 0x00, 0x4e, 0x02, 0x00, 0x00,
  0x46, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x0e,
  0x00, 0x00, 0x00};

static const gchar SSL_CLIENT_MSOC_HANDSHAKE[] = {
  0x16, 0x03, 0x01, 0x00, 0x2d, 0x01, 0x00, 0x00,
  0x29, 0x03, 0x01, 0xc1, 0xfc, 0xd5, 0xa3, 0x6d,
  0x93, 0xdd, 0x7e, 0x0b, 0x45, 0x67, 0x3f, 0xec,
  0x79, 0x85, 0xfb, 0xbc, 0x3f, 0xd6, 0x60, 0xc2,
  0xce, 0x84, 0x85, 0x08, 0x1b, 0x81, 0x21, 0xbc,
  0xaa, 0x10, 0xfb, 0x00, 0x00, 0x02, 0x00, 0x18,
  0x01, 0x00};

static void socket_close (NiceSocket *sock);
static gint socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages);
static gint socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages);
static gint socket_send_messages_reliable (NiceSocket *sock,
    const NiceAddress *to, const NiceOutputMessage *messages, guint n_messages);
static gboolean socket_is_reliable (NiceSocket *sock);

static void add_to_be_sent (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages);
static void free_to_be_sent (struct to_be_sent *tbs);


NiceSocket *
nice_pseudossl_socket_new (NiceSocket *base_socket,
    NicePseudoSSLSocketCompatibility compatibility)
{
  PseudoSSLPriv *priv;
  NiceSocket *sock;
  const gchar *buf;
  guint len;

  if (compatibility == NICE_PSEUDOSSL_SOCKET_COMPATIBILITY_MSOC) {
    buf = SSL_CLIENT_MSOC_HANDSHAKE;
    len = sizeof(SSL_CLIENT_MSOC_HANDSHAKE);
  } else if (compatibility == NICE_PSEUDOSSL_SOCKET_COMPATIBILITY_GOOGLE) {
    buf = SSL_CLIENT_GOOGLE_HANDSHAKE;
    len = sizeof(SSL_CLIENT_GOOGLE_HANDSHAKE);
  } else {
    return NULL;
  }

  sock = g_slice_new0 (NiceSocket);
  sock->priv = priv = g_slice_new0 (PseudoSSLPriv);

  priv->handshaken = FALSE;
  priv->base_socket = base_socket;
  priv->compatibility = compatibility;

  sock->type = NICE_SOCKET_TYPE_PSEUDOSSL;
  sock->fileno = priv->base_socket->fileno;
  sock->addr = priv->base_socket->addr;
  sock->send_messages = socket_send_messages;
  sock->send_messages_reliable = socket_send_messages_reliable;
  sock->recv_messages = socket_recv_messages;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

  /* We send 'to' NULL because it will always be to an already connected
   * TCP base socket, which ignores the destination */
  nice_socket_send_reliable (priv->base_socket, NULL, len, buf);

  return sock;
}


static void
socket_close (NiceSocket *sock)
{
  PseudoSSLPriv *priv = sock->priv;

  if (priv->base_socket)
    nice_socket_free (priv->base_socket);

  g_queue_foreach (&priv->send_queue, (GFunc) free_to_be_sent, NULL);
  g_queue_clear (&priv->send_queue);

  g_slice_free(PseudoSSLPriv, sock->priv);
}

static gboolean
server_handshake_valid(NiceSocket *sock, GInputVector *data)
{
  PseudoSSLPriv *priv = sock->priv;

  if (priv->compatibility == NICE_PSEUDOSSL_SOCKET_COMPATIBILITY_MSOC) {
    if (data->size == sizeof(SSL_SERVER_MSOC_HANDSHAKE)) {
      guint8 *buf = data->buffer;

      memset(buf + 11, 0, 32);
      memset(buf + 44, 0, 32);
      return memcmp(SSL_SERVER_MSOC_HANDSHAKE, data->buffer,
          sizeof(SSL_SERVER_MSOC_HANDSHAKE)) == 0;
    }
    return FALSE;
  } else {
    return data->size == sizeof(SSL_SERVER_GOOGLE_HANDSHAKE) &&
        memcmp(SSL_SERVER_GOOGLE_HANDSHAKE, data->buffer,
            sizeof(SSL_SERVER_GOOGLE_HANDSHAKE)) == 0;
  }
}

static gint
socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  PseudoSSLPriv *priv = sock->priv;

  if (priv->handshaken) {
    if (priv->base_socket) {
      /* Fast path: once we’ve done the handshake, pass straight through to the
       * base socket. */
      return nice_socket_recv_messages (priv->base_socket,
          recv_messages, n_recv_messages);
    }
  } else {
    guint8 data[MAX(sizeof(SSL_SERVER_GOOGLE_HANDSHAKE),
          sizeof(SSL_SERVER_MSOC_HANDSHAKE))];
    gint ret = -1;
    GInputVector local_recv_buf = { data, sizeof(data) };
    NiceInputMessage local_recv_message = { &local_recv_buf, 1, NULL, 0 };


    if (priv->compatibility == NICE_PSEUDOSSL_SOCKET_COMPATIBILITY_MSOC) {
      local_recv_buf.size = sizeof(SSL_SERVER_MSOC_HANDSHAKE);
    } else {
      local_recv_buf.size = sizeof(SSL_SERVER_GOOGLE_HANDSHAKE);
    }
    if (priv->base_socket) {
      ret = nice_socket_recv_messages (priv->base_socket,
          &local_recv_message, 1);
    }

    if (ret <= 0) {
      return ret;
    } else if (ret == 1 && server_handshake_valid(sock, &local_recv_buf)) {
      struct to_be_sent *tbs = NULL;
      priv->handshaken = TRUE;
      while ((tbs = g_queue_pop_head (&priv->send_queue))) {
        /* We only queue reliable data */
        nice_socket_send_reliable (priv->base_socket, &tbs->to, tbs->length,
            (const gchar *) tbs->buf);
        g_free (tbs->buf);
        g_slice_free (struct to_be_sent, tbs);
      }
    } else {
      if (priv->base_socket)
        nice_socket_free (priv->base_socket);
      priv->base_socket = NULL;

      return -1;
    }
  }
  return 0;
}

static gint
socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  PseudoSSLPriv *priv = sock->priv;

  if (priv->handshaken) {
    /* Fast path: pass directly through to the base socket once the handshake is
     * complete. */
    if (priv->base_socket == NULL)
      return -1;

    return nice_socket_send_messages (priv->base_socket, to, messages,
        n_messages);
  } else {
    return 0;
  }
  return n_messages;
}


static gint
socket_send_messages_reliable (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  PseudoSSLPriv *priv = sock->priv;

  if (priv->handshaken) {
    /* Fast path: pass directly through to the base socket once the handshake is
     * complete. */
    if (priv->base_socket == NULL)
      return -1;

    return nice_socket_send_messages_reliable (priv->base_socket, to, messages,
        n_messages);
  } else {
    add_to_be_sent (sock, to, messages, n_messages);
  }
  return n_messages;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  PseudoSSLPriv *priv = sock->priv;

  return nice_socket_is_reliable (priv->base_socket);
}


static void
add_to_be_sent (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  PseudoSSLPriv *priv = sock->priv;
  guint i;

  for (i = 0; i < n_messages; i++) {
    struct to_be_sent *tbs;
    const NiceOutputMessage *message = &messages[i];
    guint j;
    gsize offset = 0;
    gsize message_len;

    tbs = g_slice_new0 (struct to_be_sent);

    message_len = output_message_get_size (message);

   /* Compact the buffer. */
    tbs->buf = g_malloc (message_len);
    tbs->length = message_len;
    if (to != NULL)
      tbs->to = *to;
    g_queue_push_tail (&priv->send_queue, tbs);

    for (j = 0;
         (message->n_buffers >= 0 && j < (guint) message->n_buffers) ||
         (message->n_buffers < 0 && message->buffers[j].buffer != NULL);
         j++) {
      const GOutputVector *buffer = &message->buffers[j];
      gsize len;

      len = MIN (message_len - offset, buffer->size);
      memcpy (tbs->buf + offset, buffer->buffer, len);
      offset += len;
    }

    g_assert (offset == message_len);
  }
}

static void
free_to_be_sent (struct to_be_sent *tbs)
{
  g_free (tbs->buf);
  g_slice_free (struct to_be_sent, tbs);
}
