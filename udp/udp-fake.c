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

#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include "udp-fake.h"

typedef struct _UDPFakeSocketPriv UDPFakeSocketPriv;

struct _UDPFakeSocketPriv
{
  guint net_sock;
};

static gboolean
fake_send (
  NiceUDPSocket *sock,
  NiceAddress *to,
  guint len,
  const gchar *buf)
{
  write (sock->fileno, to, sizeof (NiceAddress));
  write (sock->fileno, &len, sizeof (guint));
  write (sock->fileno, buf, len);

  return TRUE;
}

static gint
fake_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  read (sock->fileno, from, sizeof (NiceAddress));
  read (sock->fileno, &len, sizeof (guint));
  read (sock->fileno, buf, len);

  return len;
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
  static int port = 1;
  UDPFakeSocketPriv *priv;

  if (socketpair (AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
    return FALSE;

  priv = g_slice_new0 (UDPFakeSocketPriv);
  priv->net_sock = fds[0];

  sock->fileno = fds[1];
  sock->addr.type = addr->type;
  sock->addr.addr_ipv4 = addr->addr_ipv4;

  if (addr->port == 0)
    sock->addr.port = port++;
  else
    sock->addr.port = addr->port;

  sock->send = fake_send;
  sock->recv = fake_recv;
  sock->priv = priv;
  sock->close = fake_close;
  return TRUE;
}

void
nice_udp_fake_socket_push_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  const gchar *buf)
{
  UDPFakeSocketPriv *priv;

  priv = (UDPFakeSocketPriv *) sock->priv;

  write (priv->net_sock, from, sizeof (NiceAddress));
  write (priv->net_sock, &len, sizeof (guint));
  write (priv->net_sock, buf, len);
}

guint
nice_udp_fake_socket_pop_send (
  NiceUDPSocket *sock,
  NiceAddress *to,
  guint len,
  gchar *buf)
{
  UDPFakeSocketPriv *priv;

  priv = (UDPFakeSocketPriv *) sock->priv;

  read (priv->net_sock, to, sizeof (NiceAddress));
  read (priv->net_sock, &len, sizeof (guint));
  read (priv->net_sock, buf, len);

  return len;
}

guint
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

void
nice_udp_fake_socket_factory_init (NiceUDPSocketFactory *man)
{
  man->init = fake_socket_init;
  man->close = fake_socket_factory_close;
  man->priv = NULL;
}

