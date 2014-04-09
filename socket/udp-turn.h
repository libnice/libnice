/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation
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

#ifndef _UDP_TURN_H
#define _UDP_TURN_H


typedef enum {
  NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9,
  NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE,
  NICE_TURN_SOCKET_COMPATIBILITY_MSN,
  NICE_TURN_SOCKET_COMPATIBILITY_OC2007,
  NICE_TURN_SOCKET_COMPATIBILITY_RFC5766,
} NiceTurnSocketCompatibility;

#include "socket.h"
#include "stun/stunmessage.h"


G_BEGIN_DECLS

guint
nice_udp_turn_socket_parse_recv_message (NiceSocket *sock, NiceSocket **from_sock,
    NiceInputMessage *message);

gsize
nice_udp_turn_socket_parse_recv (NiceSocket *sock, NiceSocket **from_sock,
    NiceAddress *from, gsize len, guint8 *buf,
    NiceAddress *recv_from, guint8 *recv_buf, gsize recv_len);

gboolean
nice_udp_turn_socket_set_peer (NiceSocket *sock, NiceAddress *peer);

NiceSocket *
nice_udp_turn_socket_new (GMainContext *ctx, NiceAddress *addr,
    NiceSocket *base_socket, NiceAddress *server_addr,
    gchar *username, gchar *password, NiceTurnSocketCompatibility compatibility);

void
nice_udp_turn_socket_set_ms_realm(NiceSocket *sock, StunMessage *msg);

void
nice_udp_turn_socket_set_ms_connection_id (NiceSocket *sock, StunMessage *msg);


G_END_DECLS

#endif /* _UDP_TURN_H */

