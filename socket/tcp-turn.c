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

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  NiceTurnSocketCompatibility compatibility;
  gchar recv_buf[65536];
  guint recv_buf_len;
  guint expecting_len;
  NiceSocket *base_socket;
} TurnTcpPriv;

#define MAX_UDP_MESSAGE_SIZE 65535

static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gboolean socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
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
  sock->send = socket_send;
  sock->recv = socket_recv;
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


static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  TurnTcpPriv *priv = sock->priv;
  int ret;
  guint padlen;

  if (priv->expecting_len == 0) {
    guint headerlen = 0;

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766)
      headerlen = 4;
    else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE)
      headerlen = 2;
    else
      return -1;

    ret = nice_socket_recv (priv->base_socket, from,
        headerlen - priv->recv_buf_len, priv->recv_buf + priv->recv_buf_len);
    if (ret < 0)
        return ret;

    priv->recv_buf_len += ret;

    if (priv->recv_buf_len < headerlen)
      return 0;

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      guint16 magic = ntohs (*(guint16*)priv->recv_buf);
      guint16 packetlen = ntohs (*(guint16*)(priv->recv_buf + 2));

      if (magic < 0x4000) {
        /* Its STUN */
        priv->expecting_len = 20 + packetlen;
      } else {
        /* Channel data */
        priv->expecting_len = 4 + packetlen;
      }
    }
    else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      guint len = ntohs (*(guint16*)priv->recv_buf);
      priv->expecting_len = len;
      priv->recv_buf_len = 0;
    }
  }

  if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766)
    padlen = (priv->expecting_len % 4) ?  4 - (priv->expecting_len % 4) : 0;
  else
    padlen = 0;

  ret = nice_socket_recv (priv->base_socket, from,
      priv->expecting_len + padlen - priv->recv_buf_len,
      priv->recv_buf + priv->recv_buf_len);

  if (ret < 0)
      return ret;

  priv->recv_buf_len += ret;

  if (priv->recv_buf_len == priv->expecting_len + padlen) {
    guint copy_len = MIN (len, priv->recv_buf_len);
    memcpy (buf, priv->recv_buf, copy_len);
    priv->expecting_len = 0;
    priv->recv_buf_len = 0;

    return copy_len;
  }

  return 0;
}

static gboolean
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  TurnTcpPriv *priv = sock->priv;
  gchar padbuf[3] = {0, 0, 0};
  int padlen = (len%4) ? 4 - (len%4) : 0;
  gchar buffer[MAX_UDP_MESSAGE_SIZE + sizeof(guint16) + sizeof(padbuf)];
  guint buffer_len = 0;

  if (priv->compatibility != NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 &&
      priv->compatibility != NICE_TURN_SOCKET_COMPATIBILITY_RFC5766)
    padlen = 0;

  if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    guint16 tmpbuf = htons (len);
    memcpy (buffer + buffer_len, (gchar *)&tmpbuf, sizeof(guint16));
    buffer_len += sizeof(guint16);
  }

  memcpy (buffer + buffer_len, buf, len);
  buffer_len += len;

  if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
    memcpy (buffer + buffer_len, padbuf, padlen);
    buffer_len += padlen;
  }
  return nice_socket_send (priv->base_socket, to, buffer_len, buffer);

}


static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}

