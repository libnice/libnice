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

#include "tcp-turn.h"
#include "agent-priv.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  NiceTurnSocketCompatibility compatibility;
  union {
    guint8 u8[65536];
    guint16 u16[32768];
  } recv_buf;
  gsize recv_buf_len;  /* in bytes */
  guint expecting_len;
  NiceSocket *base_socket;
} TurnTcpPriv;

#define MAX_UDP_MESSAGE_SIZE 65535

static void socket_close (NiceSocket *sock);
static gint socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages);
static gint socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages);
static gboolean socket_is_reliable (NiceSocket *sock);

NiceSocket *
nice_tcp_turn_socket_new (NiceSocket *base_socket,
    NiceTurnSocketCompatibility compatibility)
{
  TurnTcpPriv *priv;
  NiceSocket *sock = g_slice_new0 (NiceSocket);
  sock->priv = priv = g_slice_new0 (TurnTcpPriv);

  priv->compatibility = compatibility;
  priv->base_socket = base_socket;

  sock->fileno = priv->base_socket->fileno;
  sock->addr = priv->base_socket->addr;
  sock->send_messages = socket_send_messages;
  sock->recv_messages = socket_recv_messages;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

  return sock;
}


static void
socket_close (NiceSocket *sock)
{
  TurnTcpPriv *priv = sock->priv;

  if (priv->base_socket)
    nice_socket_free (priv->base_socket);

  g_slice_free(TurnTcpPriv, sock->priv);
}

static gssize
socket_recv_message (NiceSocket *sock, NiceInputMessage *recv_message)
{
  TurnTcpPriv *priv = sock->priv;
  gssize ret;
  guint padlen;
  GInputVector local_recv_buf;
  NiceInputMessage local_recv_message;

  if (priv->expecting_len == 0) {
    guint headerlen = 0;

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766)
      headerlen = 4;
    else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE)
      headerlen = 2;
    else
      return -1;

    local_recv_buf.buffer = priv->recv_buf.u8 + priv->recv_buf_len;
    local_recv_buf.size = headerlen - priv->recv_buf_len;
    local_recv_message.buffers = &local_recv_buf;
    local_recv_message.n_buffers = 1;
    local_recv_message.from = recv_message->from;
    local_recv_message.length = 0;

    ret = nice_socket_recv_messages (priv->base_socket, &local_recv_message, 1);
    if (ret < 0)
        return ret;

    priv->recv_buf_len += local_recv_message.length;

    if (priv->recv_buf_len < headerlen)
      return 0;

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      guint16 magic = ntohs (*priv->recv_buf.u16);
      guint16 packetlen = ntohs (*(priv->recv_buf.u16 + 1));

      if (magic < 0x4000) {
        /* Its STUN */
        priv->expecting_len = 20 + packetlen;
      } else {
        /* Channel data */
        priv->expecting_len = 4 + packetlen;
      }
    }
    else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      guint compat_len = ntohs (*priv->recv_buf.u16);
      priv->expecting_len = compat_len;
      priv->recv_buf_len = 0;
    }
  }

  if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766)
    padlen = (priv->expecting_len % 4) ?  4 - (priv->expecting_len % 4) : 0;
  else
    padlen = 0;

  local_recv_buf.buffer = priv->recv_buf.u8 + priv->recv_buf_len;
  local_recv_buf.size = priv->expecting_len + padlen - priv->recv_buf_len;
  local_recv_message.buffers = &local_recv_buf;
  local_recv_message.n_buffers = 1;
  local_recv_message.from = recv_message->from;
  local_recv_message.length = 0;

  ret = nice_socket_recv_messages (priv->base_socket, &local_recv_message, 1);
  if (ret < 0)
      return ret;

  priv->recv_buf_len += local_recv_message.length;

  if (priv->recv_buf_len == priv->expecting_len + padlen) {
    /* FIXME: Eliminate this memcpy(). */
    ret = memcpy_buffer_to_input_message (recv_message,
        priv->recv_buf.u8, priv->recv_buf_len);

    priv->expecting_len = 0;
    priv->recv_buf_len = 0;

    return ret;
  }

  return 0;
}

static gint
socket_recv_messages (NiceSocket *nicesock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  guint i;
  gboolean error = FALSE;

  for (i = 0; i < n_recv_messages; i++) {
    gssize len;

    len = socket_recv_message (nicesock, &recv_messages[i]);
    recv_messages[i].length = MAX (len, 0);

    if (len < 0)
      error = TRUE;

    if (len <= 0)
      break;
  }

  /* Was there an error processing the first message? */
  if (error && i == 0)
    return -1;

  return i;
}

static gssize
socket_send_message (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *message)
{
  TurnTcpPriv *priv = sock->priv;
  guint8 padbuf[3] = {0, 0, 0};
  GOutputVector *local_bufs;
  NiceOutputMessage local_message;
  guint j;
  gint ret;
  guint n_bufs;
  guint16 header_buf;
  guint offset = 0;

  /* Count the number of buffers. */
  if (message->n_buffers == -1) {
    n_bufs = 0;

    for (j = 0; message->buffers[j].buffer != NULL; j++)
      n_bufs++;
  } else {
    n_bufs = message->n_buffers;
  }

  /* Allocate a new array of buffers, covering all the buffers in the input
   * @message, but with an additional one for a header and one for a footer. */
  local_bufs = g_malloc_n (n_bufs + 1, sizeof (GOutputVector));
  local_message.buffers = local_bufs;
  local_message.n_buffers = n_bufs + 1;

  if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    header_buf = htons (output_message_get_size (message));
    local_bufs[0].buffer = &header_buf;
    local_bufs[0].size = sizeof (header_buf);
    offset = 1;
  } else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
    gsize message_len = output_message_get_size (message);
    gsize padlen = (message_len % 4) ? 4 - (message_len % 4) : 0;

    local_bufs[n_bufs].buffer = &padbuf;
    local_bufs[n_bufs].size = padlen;
  } else {
    local_message.n_buffers = n_bufs;
  }

  /* Copy the existing buffers across. */
  for (j = 0; j < n_bufs; j++) {
    local_bufs[j + offset].buffer = message->buffers[j].buffer;
    local_bufs[j + offset].size = message->buffers[j].size;
  }


  ret = nice_socket_send_messages (priv->base_socket, to, &local_message, 1);

  if (ret == 1)
    ret = output_message_get_size (&local_message);

  g_free (local_bufs);

  return ret;
}

static gint
socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  guint i;

  for (i = 0; i < n_messages; i++) {
    const NiceOutputMessage *message = &messages[i];
    gssize len;

    len = socket_send_message (sock, to, message);

    if (len < 0) {
      /* Error. */
      return len;
    } else if (len == 0) {
      /* EWOULDBLOCK. */
      break;
    }
  }

  return i;
}


static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}

