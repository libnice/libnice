/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2010 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 20010 Nokia Corporation. All rights reserved.

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

#ifndef _PSEUDOTCP_H
#define _PSEUDOTCP_H

#include <glib-object.h>

G_BEGIN_DECLS

typedef struct _PseudoTcpSocket PseudoTcpSocket;

typedef struct _PseudoTcpSocketClass PseudoTcpSocketClass;

GType pseudo_tcp_socket_get_type (void);

/* TYPE MACROS */
#define PSEUDO_TCP_SOCKET_TYPE \
  (pseudo_tcp_socket_get_type ())
#define PSEUDO_TCP_SOCKET(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), PSEUDO_TCP_SOCKET_TYPE, \
                              PseudoTcpSocket))
#define PSEUDO_TCP_SOCKET_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), PSEUDO_TCP_SOCKET_TYPE, \
                           PseudoTcpSocketClass))
#define IS_PSEUDO_TCP_SOCKET(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), PSEUDO_TCP_SOCKET_TYPE))
#define IS_PSEUDO_TCP_SOCKET_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), PSEUDO_TCP_SOCKET_TYPE))
#define PSEUDOTCP_SOCKET_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), PSEUDO_TCP_SOCKET_TYPE, \
                              PseudoTcpSocketClass))

struct _PseudoTcpSocketClass {
    GObjectClass parent_class;
};

typedef struct _PseudoTcpSocketPrivate PseudoTcpSocketPrivate;

struct _PseudoTcpSocket {
    GObject parent;
    PseudoTcpSocketPrivate *priv;
};

typedef enum {
  TCP_LISTEN,
  TCP_SYN_SENT,
  TCP_SYN_RECEIVED,
  TCP_ESTABLISHED,
  TCP_CLOSED
} PseudoTcpState;

typedef enum {
  WR_SUCCESS,
  WR_TOO_LARGE,
  WR_FAIL
} PseudoTcpWriteResult;

typedef struct {
  gpointer user_data;
  void  (*PseudoTcpOpened) (PseudoTcpSocket *tcp, gpointer data);
  void  (*PseudoTcpReadable) (PseudoTcpSocket *tcp, gpointer data);
  void  (*PseudoTcpWritable) (PseudoTcpSocket *tcp, gpointer data);
  void  (*PseudoTcpClosed) (PseudoTcpSocket *tcp, guint32 error, gpointer data);
  PseudoTcpWriteResult (*WritePacket) (PseudoTcpSocket *tcp,
      const gchar * buffer, guint32 len, gpointer data);
} PseudoTcpCallbacks;

PseudoTcpSocket *pseudo_tcp_socket_new (guint32 conversation,
    PseudoTcpCallbacks *callbacks);
gint pseudo_tcp_socket_connect(PseudoTcpSocket *self);
gint  pseudo_tcp_socket_recv(PseudoTcpSocket *self, char * buffer, size_t len);
gint pseudo_tcp_socket_send(PseudoTcpSocket *self, const char * buffer,
    guint32 len);
void pseudo_tcp_socket_close(PseudoTcpSocket *self, gboolean force);
int pseudo_tcp_socket_get_error(PseudoTcpSocket *self);

gboolean pseudo_tcp_socket_get_next_clock(PseudoTcpSocket *self, long *timeout);
void pseudo_tcp_socket_notify_clock(PseudoTcpSocket *self);
void pseudo_tcp_socket_notify_mtu(PseudoTcpSocket *self, guint16 mtu);
gboolean pseudo_tcp_socket_notify_packet(PseudoTcpSocket *self,
    const gchar * buffer, guint32 len);


G_END_DECLS

#endif /* _PSEUDOTCP_H */

