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

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <pthread.h>

#include <glib.h>

#include "udp-fake.h"

typedef struct _UDPFakeSocketPriv UDPFakeSocketPriv;

struct _UDPFakeSocketPriv
{
  guint net_sock;
};


static
ssize_t do_send (int fd, const void *buf, size_t len, const NiceAddress *to)
{
  ssize_t total = sizeof (*to) + sizeof (len);
  struct iovec iov[3];

  iov[0].iov_base = (void *)to;
  iov[0].iov_len = sizeof (*to);
  iov[1].iov_base = &len;
  iov[1].iov_len = sizeof (len);
  iov[2].iov_base = (void *)buf;
  iov[2].iov_len = len;
  total += len;

  if (writev (fd, iov, 3) != total)
    return -1;

  return len;
}


static
ssize_t do_recv (int fd, void *buf, size_t len, NiceAddress *from)
{
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  struct iovec iov[2];
  ssize_t res;

  iov[0].iov_base = from;
  iov[0].iov_len = sizeof (*from);
  iov[1].iov_base = &len;
  iov[1].iov_len = sizeof (len);

  pthread_mutex_lock (&lock);
  if ((readv (fd, iov, 2) != (sizeof (*from) + sizeof (len)))
   || (read (fd, buf, len) != (ssize_t)len))
    res = -1;
  else
    res = len;
  pthread_mutex_unlock (&lock);

  return len;
}


static gboolean
fake_send (
  NiceUDPSocket *sock,
  const NiceAddress *to,
  guint len,
  const gchar *buf)
{
  return do_send (sock->fileno, buf, len, to) == (ssize_t)len;
}

static gint
fake_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  return do_recv (sock->fileno, buf, len, from);
}

static void
fake_close (NiceUDPSocket *sock)
{
  UDPFakeSocketPriv *priv;

  close (sock->fileno);

  priv = (UDPFakeSocketPriv *) sock->priv;
  close (priv->net_sock);
  g_slice_free (UDPFakeSocketPriv, priv);
}

/* XXX: copied INADDR_ANY to sock->addr rather than using a valid address */
static gboolean
fake_socket_init (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr)
{
  int fds[2];
  static unsigned int port = 1;
  UDPFakeSocketPriv *priv;

  if (socketpair (AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
    return FALSE;

  priv = g_slice_new0 (UDPFakeSocketPriv);
  priv->net_sock = fds[0];

  sock->fileno = fds[1];
  if (addr)
    sock->addr = *addr;
  else
    nice_address_set_ipv4 (&sock->addr, 0);

  if (!addr || !nice_address_get_port (addr))
    nice_address_set_port (&sock->addr, port++);

  sock->send = fake_send;
  sock->recv = fake_recv;
  sock->priv = priv;
  sock->close = fake_close;
  return TRUE;
}

NICEAPI_EXPORT void
nice_udp_fake_socket_push_recv (
  NiceUDPSocket *sock,
  const NiceAddress *from,
  guint len,
  const gchar *buf)
{
  UDPFakeSocketPriv *priv;

  priv = (UDPFakeSocketPriv *) sock->priv;

  if (do_send (priv->net_sock, buf, len, from) != (ssize_t)len)
  /* Not much we can do here */
    abort ();
}

NICEAPI_EXPORT guint
nice_udp_fake_socket_pop_send (
  NiceUDPSocket *sock,
  NiceAddress *to,
  guint len,
  gchar *buf)
{
  UDPFakeSocketPriv *priv;

  priv = (UDPFakeSocketPriv *) sock->priv;

  return do_recv (priv->net_sock, buf, len, to);
}

NICEAPI_EXPORT guint
nice_udp_fake_socket_get_peer_fd (
  NiceUDPSocket *sock)
{
  UDPFakeSocketPriv *priv;

  priv = (UDPFakeSocketPriv *) sock->priv;
  return priv->net_sock;
}

static void
fake_socket_factory_close (
  G_GNUC_UNUSED
  NiceUDPSocketFactory *man)
{
}

NICEAPI_EXPORT void
nice_udp_fake_socket_factory_init (NiceUDPSocketFactory *man)
{
  man->init = fake_socket_init;
  man->close = fake_socket_factory_close;
  man->priv = NULL;
}

