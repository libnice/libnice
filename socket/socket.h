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

#ifndef _SOCKET_H
#define _SOCKET_H

#include "agent.h"
#include "address.h"
#include <gio/gio.h>

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

G_BEGIN_DECLS

typedef struct _NiceSocket NiceSocket;

typedef enum {
  NICE_SOCKET_TYPE_UDP_BSD,
  NICE_SOCKET_TYPE_TCP_BSD,
  NICE_SOCKET_TYPE_PSEUDOSSL,
  NICE_SOCKET_TYPE_HTTP,
  NICE_SOCKET_TYPE_SOCKS5,
  NICE_SOCKET_TYPE_UDP_TURN,
  NICE_SOCKET_TYPE_UDP_TURN_OVER_TCP,
  NICE_SOCKET_TYPE_TCP_ACTIVE,
  NICE_SOCKET_TYPE_TCP_PASSIVE,
  NICE_SOCKET_TYPE_TCP_SO
} NiceSocketType;

typedef void (*NiceSocketWritableCb) (NiceSocket *sock, gpointer user_data);

struct _NiceSocket
{
  NiceAddress addr;
  NiceSocketType type;
  GSocket *fileno;
  /* Implementations must handle any value of n_recv_messages, including 0. Iff
   * n_recv_messages is 0, recv_messages may be NULL. */
  gint (*recv_messages) (NiceSocket *sock,
      NiceInputMessage *recv_messages, guint n_recv_messages);
  /* As above, @n_messages may be zero. Iff so, @messages may be %NULL. */
  gint (*send_messages) (NiceSocket *sock, const NiceAddress *to,
      const NiceOutputMessage *messages, guint n_messages);
  gint (*send_messages_reliable) (NiceSocket *sock, const NiceAddress *to,
      const NiceOutputMessage *messages, guint n_messages);
  gboolean (*is_reliable) (NiceSocket *sock);
  gboolean (*can_send) (NiceSocket *sock, NiceAddress *addr);
  void (*set_writable_callback) (NiceSocket *sock,
      NiceSocketWritableCb callback, gpointer user_data);
  void (*close) (NiceSocket *sock);
  void *priv;
};


G_GNUC_WARN_UNUSED_RESULT
gint
nice_socket_recv_messages (NiceSocket *sock,
    NiceInputMessage *recv_messages, guint n_recv_messages);

gint
nice_socket_send_messages (NiceSocket *sock, const NiceAddress *addr,
    const NiceOutputMessage *messages, guint n_messages);
gint
nice_socket_send_messages_reliable (NiceSocket *sock, const NiceAddress *addr,
    const NiceOutputMessage *messages, guint n_messages);
gssize
nice_socket_recv (NiceSocket *sock, NiceAddress *from, gsize len,
    gchar *buf);
gssize
nice_socket_send (NiceSocket *sock, const NiceAddress *to, gsize len,
    const gchar *buf);
gssize
nice_socket_send_reliable (NiceSocket *sock, const NiceAddress *addr, gsize len,
    const gchar *buf);

gboolean
nice_socket_is_reliable (NiceSocket *sock);

gboolean
nice_socket_can_send (NiceSocket *sock, NiceAddress *addr);

void
nice_socket_set_writable_callback (NiceSocket *sock,
    NiceSocketWritableCb callback, gpointer user_data);

void
nice_socket_free (NiceSocket *sock);

#include "udp-bsd.h"
#include "tcp-bsd.h"
#include "tcp-active.h"
#include "tcp-passive.h"
#include "pseudossl.h"
#include "socks5.h"
#include "http.h"
#include "udp-turn.h"
#include "udp-turn-over-tcp.h"

G_END_DECLS

#endif /* _SOCKET_H */

