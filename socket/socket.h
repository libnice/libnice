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

struct _NiceSocket
{
  NiceAddress addr;
  GSocket *fileno;
  gint (*recv) (NiceSocket *sock, NiceAddress *from, guint len,
      gchar *buf);
  gboolean (*send) (NiceSocket *sock, const NiceAddress *to, guint len,
      const gchar *buf);
  gboolean (*is_reliable) (NiceSocket *sock);
  void (*close) (NiceSocket *sock);
  void *priv;
};

G_GNUC_WARN_UNUSED_RESULT
gint
nice_socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf);

gboolean
nice_socket_send (NiceSocket *sock, const NiceAddress *to,
  guint len, const gchar *buf);

gboolean
nice_socket_is_reliable (NiceSocket *sock);


void
nice_socket_free (NiceSocket *sock);

#include "udp-bsd.h"
#include "tcp-bsd.h"
#include "pseudossl.h"
#include "socks5.h"
#include "http.h"
#include "turn.h"
#include "tcp-turn.h"

G_END_DECLS

#endif /* _SOCKET_H */

