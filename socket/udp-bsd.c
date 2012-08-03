/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
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
 * Implementation of UDP socket interface using Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "udp-bsd.h"

#ifndef G_OS_WIN32
#include <unistd.h>
#endif


static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gboolean socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);

struct UdpBsdSocketPrivate
{
  NiceAddress niceaddr;
  GSocketAddress *gaddr;
};

NiceSocket *
nice_udp_bsd_socket_new (NiceAddress *addr)
{
  struct sockaddr_storage name;
  NiceSocket *sock = g_slice_new0 (NiceSocket);
  GSocket *gsock = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;
  struct UdpBsdSocketPrivate *priv;

  if (addr != NULL) {
    nice_address_copy_to_sockaddr(addr, (struct sockaddr *)&name);
  } else {
    memset (&name, 0, sizeof (name));
    name.ss_family = AF_UNSPEC;
  }

  if (name.ss_family == AF_UNSPEC || name.ss_family == AF_INET) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    name.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in);
#endif
  } else if (name.ss_family == AF_INET6) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    name.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in6);
#endif
  }

  if (gsock == NULL) {
    g_slice_free (NiceSocket, sock);
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);
  gaddr = g_socket_address_new_from_native (&name, sizeof (name));
  if (gaddr != NULL) {
    gret = g_socket_bind (gsock, gaddr, FALSE, NULL);
    g_object_unref (gaddr);
  }

  if (gret == FALSE) {
    g_slice_free (NiceSocket, sock);
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }

  gaddr = g_socket_get_local_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name, sizeof(name), NULL)) {
    g_slice_free (NiceSocket, sock);
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }

  g_object_unref (gaddr);

  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);

  priv = sock->priv = g_slice_new0 (struct UdpBsdSocketPrivate);
  nice_address_init (&priv->niceaddr);

  sock->fileno = gsock;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

  return sock;
}

static void
socket_close (NiceSocket *sock)
{
  struct UdpBsdSocketPrivate *priv = sock->priv;

  if (priv->gaddr)
    g_object_unref (priv->gaddr);
  g_slice_free (struct UdpBsdSocketPrivate, sock->priv);

  if (sock->fileno) {
    g_socket_close (sock->fileno, NULL);
    g_object_unref (sock->fileno);
    sock->fileno = NULL;
  }
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  GSocketAddress *gaddr = NULL;
  GError *gerr = NULL;
  gint recvd;

  recvd = g_socket_receive_from (sock->fileno, &gaddr, buf, len, NULL, &gerr);

  if (recvd < 0) {
    if (g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)
        || g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_FAILED))
      recvd = 0;

    g_error_free (gerr);
  }

  if (recvd > 0 && from != NULL && gaddr != NULL) {
    struct sockaddr_storage sa;

    g_socket_address_to_native (gaddr, &sa, sizeof (sa), NULL);
    nice_address_set_from_sockaddr (from, (struct sockaddr *)&sa);
  }

  if (gaddr != NULL)
    g_object_unref (gaddr);

  return recvd;
}

static gboolean
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  struct UdpBsdSocketPrivate *priv = sock->priv;
  ssize_t sent;

  if (!nice_address_is_valid (&priv->niceaddr) ||
      !nice_address_equal (&priv->niceaddr, to)) {
    struct sockaddr_storage sa;
    GSocketAddress *gaddr;

    if (priv->gaddr)
      g_object_unref (priv->gaddr);
    nice_address_copy_to_sockaddr (to, (struct sockaddr *)&sa);
    gaddr = g_socket_address_new_from_native (&sa, sizeof(sa));
    if (gaddr == NULL)
      return -1;
    priv->gaddr = gaddr;
    priv->niceaddr = *to;
  }

  sent = g_socket_send_to (sock->fileno, priv->gaddr, buf, len, NULL, NULL);

  return sent == (ssize_t)len;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return FALSE;
}

