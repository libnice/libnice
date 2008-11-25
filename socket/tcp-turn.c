/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2008 Collabora Ltd.
 *  Contact: Dafydd Harries
 *  Contact: Olivier Crete
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
 *   Olivier Crete, Collabora Ltd.
 *   Rémi Denis-Courmont, Nokia
 *   Kai Vehmanen
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
  NiceUdpTurnSocketCompatibility compatibility;
  GQueue send_queue;
  gchar recv_buf[65536];
  guint recv_buf_len;
  guint expecting_len;
  NiceAddress server_addr;
  GMainContext *context;
  GIOChannel *io_channel;
  GSource *io_source;
} TurnTcpPriv;

struct to_be_sent {
  guint length;
  gchar *buf;
};

/*** NiceSocket ***/

static gint
socket_recv (
  NiceSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  TurnTcpPriv *priv = sock->priv;
  int ret;
  guint padlen;

  if (priv->expecting_len == 0) {
    guint headerlen = 0;

    if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9)
      headerlen = 4;
    else if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE)
      headerlen = 2;
    else
      g_assert_not_reached();

    ret = recv (sock->fileno, priv->recv_buf + priv->recv_buf_len,
        headerlen - priv->recv_buf_len, 0);
    if (ret < 0) {
#ifdef G_OS_WIN32
      if (WSAGetLastError () == WSAEWOULDBLOCK)
#else
      if (errno == EAGAIN)
#endif
        return 0;
      else
        return ret;
    }

    priv->recv_buf_len += ret;

    if (priv->recv_buf_len < headerlen)
      return 0;

    if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9) {
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
    else if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      guint len = ntohs (*(guint16*)priv->recv_buf);
      priv->expecting_len = len;
      priv->recv_buf_len = 0;
    }
  }

  if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9)
    padlen = (priv->expecting_len % 4) ?  4 - (priv->expecting_len % 4) : 0;
  else
    padlen = 0;

  ret = recv (sock->fileno, priv->recv_buf + priv->recv_buf_len,
      priv->expecting_len + padlen - priv->recv_buf_len, 0);
  if (ret < 0) {
#ifdef G_OS_WIN32
    if (WSAGetLastError () == WSAEWOULDBLOCK)
#else
    if (errno == EAGAIN)
#endif
      return 0;
    else
      return ret;
  }

  priv->recv_buf_len += ret;

  if (priv->recv_buf_len == priv->expecting_len + padlen) {
    guint copy_len = MIN (len, priv->recv_buf_len);
    memcpy (buf, priv->recv_buf, copy_len);
    priv->expecting_len = 0;
    priv->recv_buf_len = 0;
    if (from)
      *from = priv->server_addr;
    return copy_len;
  }

  return 0;
}
static void
add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len, gboolean head);



/*
 * Returns:
 * -1 = error
 * 0 = have more to send
 * 1 = sent everything
 */

static gboolean
socket_send_more (
  GIOChannel *source,
  G_GNUC_UNUSED
  GIOCondition condition,
  gpointer data)
{
  NiceSocket *sock = (NiceSocket *) data;
  TurnTcpPriv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;

  while ((tbs = g_queue_pop_head (&priv->send_queue))) {
    int ret;

    ret = send (sock->fileno, tbs->buf, tbs->length, 0);

    if (ret < 0) {
#ifdef G_OS_WIN32
      if (WSAGetLastError () == WSAEWOULDBLOCK) {
#else
      if (errno == EAGAIN) {
#endif
        add_to_be_sent (sock, tbs->buf, tbs->length, TRUE);
        g_free (tbs->buf);
        g_slice_free (struct to_be_sent, tbs);
        break;
      }
    } else if (ret < (int) tbs->length) {
      add_to_be_sent (sock, tbs->buf + ret, tbs->length - ret, TRUE);
      g_free (tbs->buf);
      g_slice_free (struct to_be_sent, tbs);
      break;
    }

    g_free (tbs->buf);
    g_slice_free (struct to_be_sent, tbs);
  }

  if (g_queue_is_empty (&priv->send_queue)) {
    g_io_channel_unref (priv->io_channel);
    priv->io_channel = NULL;
    g_source_destroy (priv->io_source);
    g_source_unref (priv->io_source);
    priv->io_source = NULL;
    return FALSE;
  }

  return TRUE;
}


static void
add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len, gboolean head)
{
  TurnTcpPriv *priv = sock->priv;
  struct to_be_sent *tbs = g_slice_new (struct to_be_sent);

  if (len <= 0)
    return;

  tbs->buf = g_memdup (buf, len);
  tbs->length = len;
  if (head)
    g_queue_push_head (&priv->send_queue, tbs);
  else
    g_queue_push_tail (&priv->send_queue, tbs);

  if (priv->io_channel == NULL) {
    priv->io_channel = g_io_channel_unix_new (sock->fileno);
    priv->io_source = g_io_create_watch (priv->io_channel, G_IO_OUT);
    g_source_set_callback (priv->io_source, (GSourceFunc) socket_send_more,
        sock, NULL);
    g_source_attach (priv->io_source, priv->context);
  }
}


static gboolean
socket_send (
  NiceSocket *sock,
  const NiceAddress *to,
  guint len,
  const gchar *buf)
{
  int ret;
  TurnTcpPriv *priv = sock->priv;
  gchar padbuf[3] = {0, 0, 0};
  int padlen = (len%4) ? 4 - (len%4) : 0;

  if (priv->compatibility != NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9)
    padlen = 0;

  /* First try to send the data, don't send it later if it can be sent now
     this way we avoid allocating memory on every send */
  if (g_queue_is_empty (&priv->send_queue)) {
    if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      guint16 tmpbuf = htons (len);
      ret = send (sock->fileno, (void *) &tmpbuf, sizeof(guint16), 0);

      if (ret < 0) {
#ifdef G_OS_WIN32
        if (WSAGetLastError () == WSAEWOULDBLOCK) {
#else
        if (errno == EAGAIN) {
#endif
          add_to_be_sent (sock, (gchar *) &tmpbuf, sizeof(guint16), FALSE);
          add_to_be_sent (sock, buf, len, FALSE);
          return TRUE;
        } else {
          return FALSE;
        }
      } else if ((guint)ret < sizeof(guint16)) {
        add_to_be_sent (sock, ((gchar *) &tmpbuf) + ret,
            sizeof(guint16) - ret, FALSE);
        add_to_be_sent (sock, buf, len, FALSE);
        return TRUE;
      }
    }

    ret = send (sock->fileno, buf, len, 0);

    if (ret < 0) {
#ifdef G_OS_WIN32
      if (WSAGetLastError () == WSAEWOULDBLOCK) {
#else
      if (errno == EAGAIN) {
#endif
        add_to_be_sent (sock, buf, len, FALSE);
        add_to_be_sent (sock, padbuf, padlen, FALSE);
        return TRUE;
      } else {
        return FALSE;
      }
    } else if ((guint)ret < len) {
      add_to_be_sent (sock, buf + ret, len - ret, FALSE);
      add_to_be_sent (sock, padbuf, padlen, FALSE);
      return TRUE;
    }

    if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9 &&
        len % 4) {

      ret = send (sock->fileno, padbuf, padlen, 0);

      if (ret < 0) {
#ifdef G_OS_WIN32
        if (WSAGetLastError () == WSAEWOULDBLOCK) {
#else
        if (errno == EAGAIN) {
#endif
          add_to_be_sent (sock, padbuf, padlen, FALSE);
          return TRUE;
        } else {
          return FALSE;
        }
      } else if (ret < padlen) {
        add_to_be_sent (sock, padbuf, padlen - ret, FALSE);
        return TRUE;
      }
    }
  } else {
    if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      guint16 tmpbuf = htons (len);
      add_to_be_sent (sock, (gchar*) &tmpbuf, sizeof(guint16), FALSE);
    }
    add_to_be_sent (sock, buf, len, FALSE);
    add_to_be_sent (sock, padbuf, padlen, FALSE);
  }

  return TRUE;
}

static void
free_to_be_sent (struct to_be_sent *tbs)
{
  g_free (tbs->buf);
  g_slice_free (struct to_be_sent, tbs);
}

static void
socket_close (NiceSocket *sock)
{
  TurnTcpPriv *priv = sock->priv;
#ifdef G_OS_WIN32
  closesocket(sock->fileno);
#else
  close (sock->fileno);
#endif
  g_queue_foreach (&priv->send_queue, (GFunc) free_to_be_sent, NULL);
  g_queue_clear (&priv->send_queue);
  if (priv->io_channel)
	g_io_channel_unref (priv->io_channel);
  if (priv->io_source) {
    g_source_destroy (priv->io_source);
    g_source_unref (priv->io_source);
  }
  g_slice_free(TurnTcpPriv, sock->priv);
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}


NiceSocket *
nice_tcp_turn_socket_new (
    NiceAgent *agent,
    GMainContext *ctx,
    NiceAddress *addr,
    NiceUdpTurnSocketCompatibility compatibility)
{
  int sockfd = -1;
  int ret;
  struct sockaddr_storage name;
  guint name_len = sizeof (name);
  NiceSocket *sock = g_slice_new0 (NiceSocket);
  TurnTcpPriv *priv;

  if (addr != NULL) {
    nice_address_copy_to_sockaddr(addr, (struct sockaddr *)&name);
  } else {
    memset (&name, 0, sizeof (name));
    name.ss_family = AF_UNSPEC;
  }

  if ((sockfd == -1) &&
      ((name.ss_family == AF_UNSPEC) ||
          (name.ss_family == AF_INET))) {
    sockfd = socket (PF_INET, SOCK_STREAM, 0);
    name.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in);
#endif
  }

  if (sockfd == -1) {
    g_slice_free (NiceSocket, sock);
    return NULL;
  }

#ifdef FD_CLOEXEC
  fcntl (sockfd, F_SETFD, fcntl (sockfd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
  fcntl (sockfd, F_SETFL, fcntl (sockfd, F_GETFL) | O_NONBLOCK);
#endif

  name_len = name.ss_family == AF_INET? sizeof (struct sockaddr_in) :
      sizeof(struct sockaddr_in6);
  ret = connect (sockfd, (const struct sockaddr *)&name, name_len);

#ifdef G_OS_WIN32
  if (ret < 0 && WSAGetLastError () != WSAEINPROGRESS) {
    closesocket (sockfd);
#else
  if (ret < 0 && errno != EINPROGRESS) {
    close (sockfd);
#endif
    g_slice_free (NiceSocket, sock);
    return NULL;
  }

  name_len = name.ss_family == AF_INET? sizeof (struct sockaddr_in) :
      sizeof(struct sockaddr_in6);
  if (getsockname (sockfd, (struct sockaddr *) &name, &name_len) < 0) {
    g_slice_free (NiceSocket, sock);
#ifdef G_OS_WIN32
    closesocket(sockfd);
#else
    close (sockfd);
#endif
    return NULL;
  }

  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);

  sock->priv = priv = g_slice_new0 (TurnTcpPriv);

  priv->compatibility = compatibility;
  priv->server_addr = *addr;
  priv->context = ctx;

  sock->fileno = sockfd;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

  return sock;
}
