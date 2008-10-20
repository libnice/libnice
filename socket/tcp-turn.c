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
 * Implementation of UDP socket interface using TCP Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <arpa/inet.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "tcp-turn.h"

typedef struct {
  NiceUdpTurnSocketCompatibility compatibility;
  GQueue send_queue;
  WriteBlockedCb cb;
  gpointer user_data;
  gchar recv_buf[65536];
  guint recv_buf_len;
  guint expecting_len;
} TurnTcpPriv;

struct to_be_sent {
  guint length;
  gchar *buf;
};

/*** NiceUDPSocket ***/

static gint
socket_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  TurnTcpPriv *priv = sock->priv;
  int ret;
  int padlen;

  if (priv->expecting_len == 0) {
    int headerlen = 0;

    if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9)
      headerlen = 4;
    else if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE)
      headerlen = 2;
    else
      g_assert_not_reached();

    ret = read (sock->fileno, priv->recv_buf + priv->recv_buf_len,
        headerlen - priv->recv_buf_len);
    if (ret < 0) {
      if (errno == EAGAIN)
        return 0;
      else
        return ret;
    }

    priv->recv_buf_len += ret;

    if (ret < headerlen)
      return 0;

    if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9) {
      guint16 magic = ntohs (*(guint16*)priv->recv_buf);
      guint16 packetlen = ntohs (*(guint16*)(priv->recv_buf + 2));

      /* Its STUN */
      if (magic < 4000) {
        priv->expecting_len = 20 + packetlen;
      /* Channel data */
      }
      else {
        priv->expecting_len = 4 + packetlen;
      }
    }
    else if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      guint len = ntohs (*(guint16*)priv->recv_buf);
      priv->expecting_len = len;
      priv->recv_buf_len = 0;
    }
  }

  padlen = (priv->expecting_len % 4) ?  4 - priv->expecting_len % 4 : 0;

  ret = read (sock->fileno, priv->recv_buf + priv->recv_buf_len,
      priv->expecting_len + padlen - priv->recv_buf_len);
  if (ret < 0) {
    if (errno == EAGAIN)
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
    return copy_len;
  }

  return 0;
}

static void
add_to_be_sent (NiceUDPSocket *sock, const gchar *buf, guint len)
{
  TurnTcpPriv *priv = sock->priv;
  struct to_be_sent *tbs = g_slice_new (struct to_be_sent);

  tbs->buf = g_memdup (buf, len);
  tbs->length = len;
  g_queue_push_tail (&priv->send_queue, tbs);

  priv->cb (sock, priv->user_data);
}

/*
 * Returns:
 * -1 = error
 * 0 = have more to send
 * 1 = sent everything
 */

gint
socket_send_more (NiceUDPSocket *sock)
{
  TurnTcpPriv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;

  while ((tbs = g_queue_pop_head (&priv->send_queue))) {
    int ret;

    ret = write (sock->fileno, tbs->buf, tbs->length);

    if (ret <= 0) {
      if (errno == EAGAIN)
        return 0;
      else
        return -1;
    }

    g_slice_free (struct to_be_sent, tbs);
  }

  return 1;
}

static gboolean
socket_send (
  NiceUDPSocket *sock,
  const NiceAddress *to,
  guint len,
  const gchar *buf)
{
  int ret;
  TurnTcpPriv *priv = sock->priv;

  if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    guint16 tmpbuf = htons (len);
    ret = write (sock->fileno, &tmpbuf, 2);

    if (ret <= 0) {
      if (errno == EAGAIN) {
        add_to_be_sent (sock, (gchar*) &tmpbuf, 2);
        add_to_be_sent (sock, buf, len);
        return TRUE;
      } else {
        return FALSE;
      }
    }

    if ((guint)ret != len)
      return FALSE;
  }

  ret = write (sock->fileno, buf, len);

  if (ret <= 0) {
    if (errno == EAGAIN) {
      add_to_be_sent (sock, buf, len);
      return TRUE;
    } else {
      return FALSE;
    }
  }

  if ((guint)ret != len)
    return FALSE;

  if (priv->compatibility == NICE_UDP_TURN_SOCKET_COMPATIBILITY_DRAFT9 &&
      len % 4) {
    gchar padbuf[3] = {0, 0, 0};
    int padlen = (len%4) ? 4 - (len%4) : 0;

    ret = write (sock->fileno, padbuf, padlen);

    if (ret <= 0) {
      if (errno == EAGAIN) {
        add_to_be_sent (sock, padbuf, padlen);
        return TRUE;
      } else {
        return FALSE;
      }
    }
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
socket_close (NiceUDPSocket *sock)
{
  TurnTcpPriv *priv = sock->priv;
  close (sock->fileno);
  g_queue_foreach (&priv->send_queue, (GFunc) free_to_be_sent, NULL);
  g_queue_clear (&priv->send_queue);
  g_slice_free(TurnTcpPriv, sock->priv);
}


gboolean
nice_tcp_turn_create_socket_full (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *local_addr,
  NiceAddress *remote_addr,
  NiceUdpTurnSocketCompatibility compatibility,
  WriteBlockedCb cb,
  gpointer user_data)
{
  int sockfd = -1;
  struct sockaddr_storage name;
  guint name_len = sizeof (name);
  struct sockaddr_storage remote_name;
  guint remote_name_len = sizeof (remote_name);
  int ret;
  TurnTcpPriv *priv;

  if (local_addr != NULL)
    {
      nice_address_copy_to_sockaddr(local_addr, (struct sockaddr *)&name);
    }
  else
    {
      memset (&name, 0, sizeof (name));
      name.ss_family = AF_UNSPEC;
    }

  if ((sockfd == -1)
   && ((name.ss_family == AF_UNSPEC) || (name.ss_family == AF_INET)))
    {
      sockfd = socket (PF_INET, SOCK_STREAM, 0);
      name.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
      name.ss_len = sizeof (struct sockaddr_in);
#endif
    }

  if (sockfd == -1)
    return FALSE;

#ifdef FD_CLOEXEC
  fcntl (sockfd, F_SETFD, fcntl (sockfd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
  fcntl (sockfd, F_SETFL, fcntl (sockfd, F_GETFL) | O_NONBLOCK);
#endif

  if(bind (sockfd, (struct sockaddr *) &name, sizeof (name)) != 0)
    {
      close (sockfd);
      return FALSE;
    }

  if (getsockname (sockfd, (struct sockaddr *) &name, &name_len) != 0)
    {
      close (sockfd);
      return FALSE;
    }

  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);

  nice_address_copy_to_sockaddr (remote_addr, (struct sockaddr *)&remote_name);

  ret = connect (sockfd, (const struct sockaddr *)&remote_name,
      remote_name_len);

  if (ret < 0 && errno != EINPROGRESS) {
    close (sockfd);
    return FALSE;
  }

  sock->priv = priv = g_slice_new0 (TurnTcpPriv);

  priv->cb = cb;
  priv->user_data = user_data;
  priv->compatibility = compatibility;

  sock->fileno = sockfd;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->close = socket_close;
  return TRUE;
}

/*** NiceUDPSocketFactory ***/


static void
socket_factory_close (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man)
{
  (void)man;
}


static gboolean
socket_factory_init_socket (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr)
{
  return FALSE;
}

NICEAPI_EXPORT void
nice_tcp_turn_socket_factory_init (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man)
{
  man->init = socket_factory_init_socket;
  man->close = socket_factory_close;
}

