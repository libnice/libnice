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
static gint socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages);
static gint socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages);
static gint socket_send_messages_reliable (NiceSocket *sock,
    const NiceAddress *to, const NiceOutputMessage *messages, guint n_messages);
static gboolean socket_is_reliable (NiceSocket *sock);
static gboolean socket_can_send (NiceSocket *sock, NiceAddress *addr);
static void socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data);

struct UdpBsdSocketPrivate
{
  NiceAddress niceaddr;
  GSocketAddress *gaddr;
};

NiceSocket *
nice_udp_bsd_socket_new (NiceAddress *addr)
{
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } name;
  NiceSocket *sock = g_slice_new0 (NiceSocket);
  GSocket *gsock = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;
  struct UdpBsdSocketPrivate *priv;

  if (addr != NULL) {
    nice_address_copy_to_sockaddr(addr, &name.addr);
  } else {
    memset (&name, 0, sizeof (name));
    name.storage.ss_family = AF_UNSPEC;
  }

  if (name.storage.ss_family == AF_UNSPEC || name.storage.ss_family == AF_INET) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    name.storage.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
    name.storage.ss_len = sizeof (struct sockaddr_in);
#endif
  } else if (name.storage.ss_family == AF_INET6) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    name.storage.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
    name.storage.ss_len = sizeof (struct sockaddr_in6);
#endif
  }

  if (gsock == NULL) {
    g_slice_free (NiceSocket, sock);
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);
  gaddr = g_socket_address_new_from_native (&name.addr, sizeof (name));
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
      !g_socket_address_to_native (gaddr, &name.addr, sizeof(name), NULL)) {
    g_slice_free (NiceSocket, sock);
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }

  g_object_unref (gaddr);

  nice_address_set_from_sockaddr (&sock->addr, &name.addr);

  priv = sock->priv = g_slice_new0 (struct UdpBsdSocketPrivate);
  nice_address_init (&priv->niceaddr);

  sock->type = NICE_SOCKET_TYPE_UDP_BSD;
  sock->fileno = gsock;
  sock->send_messages = socket_send_messages;
  sock->send_messages_reliable = socket_send_messages_reliable;
  sock->recv_messages = socket_recv_messages;
  sock->is_reliable = socket_is_reliable;
  sock->can_send = socket_can_send;
  sock->set_writable_callback = socket_set_writable_callback;
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
  sock->priv = NULL;

  if (sock->fileno) {
    g_socket_close (sock->fileno, NULL);
    g_object_unref (sock->fileno);
    sock->fileno = NULL;
  }
}

static gint
socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  guint i;
  gboolean error = FALSE;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return 0;

  /* Read messages into recv_messages until one fails or would block, or we
   * reach the end. */
  for (i = 0; i < n_recv_messages; i++) {
    NiceInputMessage *recv_message = &recv_messages[i];
    GSocketAddress *gaddr = NULL;
    GError *gerr = NULL;
    gssize recvd;
    gint flags = G_SOCKET_MSG_NONE;

    recvd = g_socket_receive_message (sock->fileno,
        (recv_message->from != NULL) ? &gaddr : NULL,
        recv_message->buffers, recv_message->n_buffers, NULL, NULL,
        &flags, NULL, &gerr);

    recv_message->length = MAX (recvd, 0);

    if (recvd < 0) {
      if (g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
        recvd = 0;
      else
        error = TRUE;

      g_error_free (gerr);
    }

    if (recvd > 0 && recv_message->from != NULL && gaddr != NULL) {
      union {
        struct sockaddr_storage storage;
        struct sockaddr addr;
      } sa;

      g_socket_address_to_native (gaddr, &sa.addr, sizeof (sa), NULL);
      nice_address_set_from_sockaddr (recv_message->from, &sa.addr);
    }

    if (gaddr != NULL)
      g_object_unref (gaddr);

    /* Return early on error or EWOULDBLOCK. */
    if (recvd <= 0)
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
  struct UdpBsdSocketPrivate *priv = sock->priv;
  GError *child_error = NULL;
  gssize len;

  /* Socket has been closed: */
  if (priv == NULL)
    return -1;

  if (!nice_address_is_valid (&priv->niceaddr) ||
      !nice_address_equal (&priv->niceaddr, to)) {
    union {
      struct sockaddr_storage storage;
      struct sockaddr addr;
    } sa;
    GSocketAddress *gaddr;

    if (priv->gaddr)
      g_object_unref (priv->gaddr);

    nice_address_copy_to_sockaddr (to, &sa.addr);
    gaddr = g_socket_address_new_from_native (&sa.addr, sizeof(sa));
    priv->gaddr = gaddr;

    if (gaddr == NULL)
      return -1;

    priv->niceaddr = *to;
  }

  len = g_socket_send_message (sock->fileno, priv->gaddr, message->buffers,
      message->n_buffers, NULL, 0, G_SOCKET_MSG_NONE, NULL, &child_error);

  if (len < 0) {
    if (g_error_matches (child_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
      len = 0;

    g_error_free (child_error);
  }

  return len;
}

static gint
socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  guint i;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return -1;

  for (i = 0; i < n_messages; i++) {
    const NiceOutputMessage *message = &messages[i];
    gssize len;

    len = socket_send_message (sock, to, message);

    if (len < 0) {
      /* Error. */
      if (i > 0)
        break;
      return len;
    } else if (len == 0) {
      /* EWOULDBLOCK. */
      break;
    }
  }

  return i;
}

static gint
socket_send_messages_reliable (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  return -1;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return FALSE;
}

static gboolean
socket_can_send (NiceSocket *sock, NiceAddress *addr)
{
  return TRUE;
}

static void
socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data)
{
}

