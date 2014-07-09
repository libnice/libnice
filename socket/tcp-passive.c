/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2012 Collabora Ltd.
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
 *   George Kiagiadakis, Collabora Ltd.
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

#include "tcp-passive.h"
#include "agent-priv.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  GMainContext *context;
  GHashTable *connections;
  NiceSocketWritableCb writable_cb;
  gpointer writable_data;
} TcpPassivePriv;


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

static guint nice_address_hash (const NiceAddress * key);

NiceSocket *
nice_tcp_passive_socket_new (GMainContext *ctx, NiceAddress *addr)
{
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } name;
  NiceSocket *sock;
  TcpPassivePriv *priv;
  GSocket *gsock = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;

  if (addr != NULL) {
    nice_address_copy_to_sockaddr(addr, &name.addr);
  } else {
    memset (&name, 0, sizeof (name));
    name.storage.ss_family = AF_UNSPEC;
  }

  if (name.storage.ss_family == AF_UNSPEC || name.storage.ss_family == AF_INET) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_STREAM,
        G_SOCKET_PROTOCOL_TCP, NULL);

    name.storage.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
    name.storage.ss_len = sizeof (struct sockaddr_in);
#endif
  } else if (name.storage.ss_family == AF_INET6) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_STREAM,
        G_SOCKET_PROTOCOL_TCP, NULL);
    name.storage.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
    name.storage.ss_len = sizeof (struct sockaddr_in6);
#endif
  }

  if (gsock == NULL) {
    return NULL;
  }

  gaddr = g_socket_address_new_from_native (&name.addr, sizeof (name));

  if (gaddr == NULL) {
    g_object_unref (gsock);
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);

  gret = g_socket_bind (gsock, gaddr, FALSE, NULL) &&
      g_socket_listen (gsock, NULL);
  g_object_unref (gaddr);

  if (gret == FALSE) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }

  gaddr = g_socket_get_local_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name.addr, sizeof (name), NULL)) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }
  g_object_unref (gaddr);

  if (ctx == NULL) {
    ctx = g_main_context_default ();
  }

  sock = g_slice_new0 (NiceSocket);

  nice_address_set_from_sockaddr (&sock->addr, &name.addr);

  sock->priv = priv = g_slice_new0 (TcpPassivePriv);
  priv->context = g_main_context_ref (ctx);
  priv->connections = g_hash_table_new_full ((GHashFunc) nice_address_hash,
      (GEqualFunc) nice_address_equal, (
          GDestroyNotify) nice_address_free, NULL);
  priv->writable_cb = NULL;
  priv->writable_data = NULL;

  sock->type = NICE_SOCKET_TYPE_TCP_PASSIVE;
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
  TcpPassivePriv *priv = sock->priv;

  if (priv->context)
    g_main_context_unref (priv->context);
  g_hash_table_unref (priv->connections);

  g_slice_free (TcpPassivePriv, sock->priv);
}

static gint socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  return -1;
}

static gint socket_send_messages (NiceSocket *sock, const NiceAddress *to,
    const NiceOutputMessage *messages, guint n_messages)
{
  TcpPassivePriv *priv = sock->priv;

  if (to) {
    NiceSocket *peer_socket = g_hash_table_lookup (priv->connections, to);
    if (peer_socket)
      return nice_socket_send_messages (peer_socket, to, messages, n_messages);
  }
  return -1;
}

static gint socket_send_messages_reliable (NiceSocket *sock,
    const NiceAddress *to, const NiceOutputMessage *messages, guint n_messages)
{
  TcpPassivePriv *priv = sock->priv;

  if (to) {
    NiceSocket *peer_socket = g_hash_table_lookup (priv->connections, to);
    if (peer_socket)
      return nice_socket_send_messages_reliable (peer_socket, to, messages,
          n_messages);
  }
  return -1;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}

static gboolean
socket_can_send (NiceSocket *sock, NiceAddress *addr)
{
  TcpPassivePriv *priv = sock->priv;
  NiceSocket *peer_socket = NULL;

  /* FIXME: Danger if child socket was closed */
  if (addr)
    peer_socket = g_hash_table_lookup (priv->connections, addr);
  if (peer_socket)
    return nice_socket_can_send (peer_socket, addr);
  return FALSE;
}

static void
_child_writable_cb (NiceSocket *child, gpointer data)
{
  NiceSocket *sock = data;
  TcpPassivePriv *priv = sock->priv;

  if (priv->writable_cb)
    priv->writable_cb (sock, priv->writable_data);
}

static void
socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data)
{
  TcpPassivePriv *priv = sock->priv;

  priv->writable_cb = callback;
  priv->writable_data = user_data;
}

NiceSocket *
nice_tcp_passive_socket_accept (NiceSocket *sock)
{
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } name;
  TcpPassivePriv *priv = sock->priv;
  GSocket *gsock = NULL;
  GSocketAddress *gaddr;
  NiceAddress remote_addr;
  NiceSocket *new_socket = NULL;

  gsock = g_socket_accept (sock->fileno, NULL, NULL);

  if (gsock == NULL) {
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);

  gaddr = g_socket_get_remote_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name.addr, sizeof (name), NULL)) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }
  g_object_unref (gaddr);

  nice_address_set_from_sockaddr (&remote_addr, &name.addr);

  new_socket = nice_tcp_bsd_socket_new_from_gsock (priv->context, gsock,
      &sock->addr, &remote_addr, TRUE);
  g_object_unref (gsock);

  if (new_socket) {
    NiceAddress *key = nice_address_dup (&remote_addr);

    nice_socket_set_writable_callback (new_socket, _child_writable_cb, sock);
    g_hash_table_insert (priv->connections, key, new_socket);
  }
  return new_socket;
}

static guint nice_address_hash (const NiceAddress * key)
{
  gchar ip[INET6_ADDRSTRLEN];
  gchar *str;
  guint hash;

  nice_address_to_string (key, ip);
  str = g_strdup_printf ("%s:%u", ip, nice_address_get_port (key));
  hash = g_str_hash (str);
  g_free (str);

  return hash;
}
