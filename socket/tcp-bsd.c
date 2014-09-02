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

#include "tcp-bsd.h"
#include "agent-priv.h"
#include "socket-priv.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  NiceAddress remote_addr;
  GQueue send_queue;
  GMainContext *context;
  GSource *io_source;
  gboolean error;
  gboolean reliable;
  NiceSocketWritableCb writable_cb;
  gpointer writable_data;
} TcpPriv;

#define MAX_QUEUE_LENGTH 20

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

static gboolean socket_send_more (GSocket *gsocket, GIOCondition condition,
    gpointer data);

NiceSocket *
nice_tcp_bsd_socket_new_from_gsock (GMainContext *ctx, GSocket *gsock,
    NiceAddress *local_addr, NiceAddress *remote_addr, gboolean reliable)
{
  NiceSocket *sock;
  TcpPriv *priv;

  g_return_val_if_fail (G_IS_SOCKET (gsock), NULL);

  sock = g_slice_new0 (NiceSocket);
  sock->priv = priv = g_slice_new0 (TcpPriv);

  if (ctx == NULL)
    ctx = g_main_context_default ();
  priv->context = g_main_context_ref (ctx);
  priv->remote_addr = *remote_addr;
  priv->error = FALSE;
  priv->reliable = reliable;
  priv->writable_cb = NULL;
  priv->writable_data = NULL;

  sock->type = NICE_SOCKET_TYPE_TCP_BSD;
  sock->fileno = g_object_ref (gsock);
  sock->addr = *local_addr;
  sock->send_messages = socket_send_messages;
  sock->send_messages_reliable = socket_send_messages_reliable;
  sock->recv_messages = socket_recv_messages;
  sock->is_reliable = socket_is_reliable;
  sock->can_send = socket_can_send;
  sock->set_writable_callback = socket_set_writable_callback;
  sock->close = socket_close;

  return sock;
}

NiceSocket *
nice_tcp_bsd_socket_new (GMainContext *ctx, NiceAddress *local_addr,
    NiceAddress *remote_addr, gboolean reliable)
{
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } name;
  NiceSocket *sock;
  GSocket *gsock = NULL;
  GError *gerr = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;

  if (remote_addr == NULL) {
    /* We can't connect a tcp socket with no destination address */
    return NULL;
  }

  nice_address_copy_to_sockaddr (remote_addr, &name.addr);

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

  gret = g_socket_connect (gsock, gaddr, NULL, &gerr);
  g_object_unref (gaddr);

  if (gret == FALSE) {
    if (g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_PENDING) == FALSE) {
      g_error_free (gerr);
      g_socket_close (gsock, NULL);
      g_object_unref (gsock);
      return NULL;
    }
    g_error_free (gerr);
  }

  nice_address_copy_to_sockaddr (local_addr, &name.addr);
  gaddr = g_socket_address_new_from_native (&name.addr, sizeof (name));
  if (gaddr == NULL) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }
  g_socket_bind (gsock, gaddr, FALSE, NULL);
  g_object_unref (gaddr);

  sock = nice_tcp_bsd_socket_new_from_gsock (ctx, gsock, local_addr, remote_addr,
      reliable);
  g_object_unref (gsock);

  return sock;
}


static void
socket_close (NiceSocket *sock)
{
  TcpPriv *priv = sock->priv;

  if (sock->fileno) {
    g_socket_close (sock->fileno, NULL);
    g_object_unref (sock->fileno);
    sock->fileno = NULL;
  }
  if (priv->io_source) {
    g_source_destroy (priv->io_source);
    g_source_unref (priv->io_source);
  }

  nice_socket_free_send_queue (&priv->send_queue);

  if (priv->context)
    g_main_context_unref (priv->context);

  g_slice_free(TcpPriv, sock->priv);
}

static gint
socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages)
{
  TcpPriv *priv = sock->priv;
  guint i;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return 0;

  /* Don't try to access the socket if it had an error */
  if (priv->error)
    return -1;

  for (i = 0; i < n_recv_messages; i++) {
    gint flags = G_SOCKET_MSG_NONE;
    GError *gerr = NULL;
    gssize len;

    len = g_socket_receive_message (sock->fileno, NULL,
        recv_messages[i].buffers, recv_messages[i].n_buffers,
        NULL, NULL, &flags, NULL, &gerr);

    recv_messages[i].length = MAX (len, 0);

    /* recv returns 0 when the peer performed a shutdown.. we must return -1
     * here so that the agent destroys the g_source */
    if (len == 0) {
      priv->error = TRUE;
      break;
    }

    if (len < 0) {
      if (g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
        len = 0;

      g_error_free (gerr);
      return len;
    }

    if (recv_messages[i].from)
      *recv_messages[i].from = priv->remote_addr;
  }

  /* Was there an error processing the first message? */
  if (priv->error && i == 0)
    return -1;

  return i;
}

static gssize
socket_send_message (NiceSocket *sock,
    const NiceOutputMessage *message, gboolean reliable)
{
  TcpPriv *priv = sock->priv;
  gssize ret;
  GError *gerr = NULL;
  gsize message_len;

  /* Socket has been closed: */
  if (sock->priv == NULL)
    return -1;

  /* Don't try to access the socket if it had an error, otherwise we risk a
   * crash with SIGPIPE (Broken pipe) */
  if (priv->error)
    return -1;

  message_len = output_message_get_size (message);

  /* First try to send the data, don't send it later if it can be sent now
   * this way we avoid allocating memory on every send */
  if (g_queue_is_empty (&priv->send_queue)) {
    ret = g_socket_send_message (sock->fileno, NULL, message->buffers,
        message->n_buffers, NULL, 0, G_SOCKET_MSG_NONE, NULL, &gerr);

    if (ret < 0) {
      if (g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) ||
          g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_FAILED)) {
        /* Queue the message and send it later. */
        nice_socket_queue_send_with_callback (&priv->send_queue,
            message, 0, message_len, FALSE, sock->fileno, &priv->io_source,
            priv->context, (GSourceFunc) socket_send_more, sock);
        ret = message_len;
      }

      g_error_free (gerr);
    } else if ((gsize) ret < message_len) {
      /* Partial send. */
      nice_socket_queue_send_with_callback (&priv->send_queue,
          message, ret, message_len, TRUE, sock->fileno, &priv->io_source,
          priv->context, (GSourceFunc) socket_send_more, sock);
      ret = message_len;
    }
  } else {
    /* Only queue if we're sending reliably  */
    if (reliable) {
      /* Queue the message and send it later. */
      nice_socket_queue_send_with_callback (&priv->send_queue,
          message, 0, message_len, FALSE, sock->fileno, &priv->io_source,
          priv->context, (GSourceFunc) socket_send_more, sock);
      ret = message_len;
    } else {
      /* non reliable send, so we shouldn't queue the message */
      ret = 0;
    }
  }

  return ret;
}

/* Data sent to this function must be a single entity because buffers can be
 * dropped if the bandwidth isn't fast enough. So do not send a message in
 * multiple chunks. */
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

    len = socket_send_message (sock, message, FALSE);

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
  guint i;

  for (i = 0; i < n_messages; i++) {
    if (socket_send_message (sock, &messages[i], TRUE) < 0) {
      /* Error. */
      return -1;
    }
  }

  return i;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  TcpPriv *priv = sock->priv;

  return priv->reliable;
}

static gboolean
socket_can_send (NiceSocket *sock, NiceAddress *addr)
{
  TcpPriv *priv = sock->priv;

  return g_queue_is_empty (&priv->send_queue);
}

static void
socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data)
{
  TcpPriv *priv = sock->priv;

  priv->writable_cb = callback;
  priv->writable_data = user_data;
}

static gboolean
socket_send_more (
  GSocket *gsocket,
  GIOCondition condition,
  gpointer data)
{
  NiceSocket *sock = (NiceSocket *) data;
  TcpPriv *priv = sock->priv;

  agent_lock ();

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in tcp-bsd.c:socket_send_more");
    agent_unlock ();
    return FALSE;
  }

  /* connection hangs up or queue was emptied */
  if (condition & G_IO_HUP ||
      nice_socket_flush_send_queue_to_socket (sock->fileno,
          &priv->send_queue)) {
    g_source_destroy (priv->io_source);
    g_source_unref (priv->io_source);
    priv->io_source = NULL;

    agent_unlock ();

    if (priv->writable_cb)
      priv->writable_cb (sock, priv->writable_data);

    return FALSE;
  }

  agent_unlock ();
  return TRUE;
}
