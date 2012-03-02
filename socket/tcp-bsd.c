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

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  NiceAddress server_addr;
  GQueue send_queue;
  GMainContext *context;
  GSource *io_source;
  gboolean error;
} TcpPriv;

struct to_be_sent {
  guint length;
  gchar *buf;
  gboolean can_drop;
};

#define MAX_QUEUE_LENGTH 20

static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gboolean socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);


static void add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len,
    gboolean head);
static void free_to_be_sent (struct to_be_sent *tbs);
static gboolean socket_send_more (GSocket *gsocket, GIOCondition condition,
    gpointer data);

NiceSocket *
nice_tcp_bsd_socket_new (GMainContext *ctx, NiceAddress *addr)
{
  struct sockaddr_storage name;
  NiceSocket *sock;
  TcpPriv *priv;
  GSocket *gsock = NULL;
  GError *gerr = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;

  if (addr == NULL) {
    /* We can't connect a tcp socket with no destination address */
    return NULL;
  }

  sock = g_slice_new0 (NiceSocket);

  nice_address_copy_to_sockaddr (addr, (struct sockaddr *)&name);

  if (gsock == NULL) {
    if (name.ss_family == AF_UNSPEC || name.ss_family == AF_INET) {
      gsock = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_STREAM,
          G_SOCKET_PROTOCOL_TCP, NULL);

      name.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
      name.ss_len = sizeof (struct sockaddr_in);
#endif
    } else if (name.ss_family == AF_INET6) {
      gsock = g_socket_new (G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_STREAM,
          G_SOCKET_PROTOCOL_TCP, NULL);
      name.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
      name.ss_len = sizeof (struct sockaddr_in6);
#endif
    }
  }

  if (gsock == NULL) {
    g_slice_free (NiceSocket, sock);
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);

  gaddr = g_socket_address_new_from_native (&name, sizeof (name));

  if (gaddr != NULL) {
    gret = g_socket_connect (gsock, gaddr, NULL, &gerr);
    g_object_unref (gaddr);
  }

  if (gret == FALSE) {
    if (g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_PENDING) == FALSE) {
      g_socket_close (gsock, NULL);
      g_object_unref (gsock);
      g_slice_free (NiceSocket, sock);
      return NULL;
    }
    g_error_free(gerr);
  }

  gaddr = g_socket_get_local_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name, sizeof (name), NULL)) {
    g_slice_free (NiceSocket, sock);
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }
  g_object_unref (gaddr);

  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);

  sock->priv = priv = g_slice_new0 (TcpPriv);

  priv->context = g_main_context_ref (ctx);
  priv->server_addr = *addr;
  priv->error = FALSE;

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
  g_queue_foreach (&priv->send_queue, (GFunc) free_to_be_sent, NULL);
  g_queue_clear (&priv->send_queue);

  if (priv->context)
    g_main_context_unref (priv->context);

  g_slice_free(TcpPriv, sock->priv);
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  TcpPriv *priv = sock->priv;
  int ret;
  GError *gerr = NULL;

  /* Don't try to access the socket if it had an error */
  if (priv->error)
    return -1;

  ret = g_socket_receive (sock->fileno, buf, len, NULL, &gerr);

  /* recv returns 0 when the peer performed a shutdown.. we must return -1 here
   * so that the agent destroys the g_source */
  if (ret == 0) {
    priv->error = TRUE;
    return -1;
  }

  if (ret < 0) {
    if(g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
      ret = 0;

    g_error_free (gerr);
    return ret;
  }

  if (from)
    *from = priv->server_addr;
  return ret;
}

/* Data sent to this function must be a single entity because buffers can be
 * dropped if the bandwidth isn't fast enough. So do not send a message in
 * multiple chunks. */
static gboolean
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  TcpPriv *priv = sock->priv;
  int ret;
  GError *gerr = NULL;

  /* Don't try to access the socket if it had an error, otherwise we risk a
     crash with SIGPIPE (Broken pipe) */
  if (priv->error)
    return -1;

  /* First try to send the data, don't send it later if it can be sent now
     this way we avoid allocating memory on every send */
  if (g_queue_is_empty (&priv->send_queue)) {
    ret = g_socket_send (sock->fileno, buf, len, NULL, &gerr);
    if (ret < 0) {
      if(g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)
         || g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_FAILED)) {
        add_to_be_sent (sock, buf, len, FALSE);
        g_error_free (gerr);
        return TRUE;
      } else {
        g_error_free (gerr);
        return FALSE;
      }
    } else if ((guint)ret < len) {
      add_to_be_sent (sock, buf + ret, len - ret, TRUE);
      return TRUE;
    }
  } else {
    if (g_queue_get_length(&priv->send_queue) >= MAX_QUEUE_LENGTH) {
      int peek_idx = 0;
      struct to_be_sent *tbs = NULL;
      while ((tbs = g_queue_peek_nth (&priv->send_queue, peek_idx)) != NULL) {
        if (tbs->can_drop) {
          tbs = g_queue_pop_nth (&priv->send_queue, peek_idx);
          g_free (tbs->buf);
          g_slice_free (struct to_be_sent, tbs);
          break;
        } else {
          peek_idx++;
        }
      }
    }
    add_to_be_sent (sock, buf, len, FALSE);
  }

  return TRUE;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}


/*
 * Returns:
 * -1 = error
 * 0 = have more to send
 * 1 = sent everything
 */

static gboolean
socket_send_more (
  GSocket *gsocket,
  GIOCondition condition,
  gpointer data)
{
  NiceSocket *sock = (NiceSocket *) data;
  TcpPriv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;
  GError *gerr = NULL;

  agent_lock ();

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in tcp-bsd.c:socket_send_more");
    agent_unlock ();
    return FALSE;
  }

  while ((tbs = g_queue_pop_head (&priv->send_queue)) != NULL) {
    int ret;

    if(condition & G_IO_HUP) {
      /* connection hangs up */
      ret = -1;
    } else {
      ret = g_socket_send (sock->fileno, tbs->buf, tbs->length, NULL, &gerr);
    }

    if (ret < 0) {
      if(gerr != NULL &&
          g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
        add_to_be_sent (sock, tbs->buf, tbs->length, TRUE);
        g_free (tbs->buf);
        g_slice_free (struct to_be_sent, tbs);
        g_error_free (gerr);
        break;
      }
      g_error_free (gerr);
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
    g_source_destroy (priv->io_source);
    g_source_unref (priv->io_source);
    priv->io_source = NULL;

    agent_unlock ();
    return FALSE;
  }

  agent_unlock ();
  return TRUE;
}


static void
add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len, gboolean head)
{
  TcpPriv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;

  if (len <= 0)
    return;

  tbs = g_slice_new0 (struct to_be_sent);
  tbs->buf = g_memdup (buf, len);
  tbs->length = len;
  tbs->can_drop = !head;
  if (head)
    g_queue_push_head (&priv->send_queue, tbs);
  else
    g_queue_push_tail (&priv->send_queue, tbs);

  if (priv->io_source == NULL) {
    priv->io_source = g_socket_create_source(sock->fileno, G_IO_OUT, NULL);
    g_source_set_callback (priv->io_source, (GSourceFunc) socket_send_more,
        sock, NULL);
    g_source_attach (priv->io_source, priv->context);
  }
}



static void
free_to_be_sent (struct to_be_sent *tbs)
{
  g_free (tbs->buf);
  g_slice_free (struct to_be_sent, tbs);
}

