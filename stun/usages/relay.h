/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Rémi Denis-Courmont
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
 *   Rémi Denis-Courmont, Nokia
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

#ifndef STUN_RELAY_H
# define STUN_RELAY_H 1

/**
 * @file relay.h
 * @brief STUN relay usage (TURN)
 */

typedef struct turn_s turn_t;

typedef enum
{
	TURN_PROTO_TCP=6,
	TURN_PROTO_UDP=17
} turn_proto_t;

# ifdef __cplusplus
extern "C" {
# endif

turn_t *turn_socket (int fd, int family, turn_proto_t proto,
                     const struct sockaddr *restrict srv, socklen_t srvlen);

int turn_setbandwidth (turn_t *ctx, unsigned kbits);
int turn_setrealm (turn_t *restrict ctx, const char *realm);
int turn_setusername (turn_t *restrict ctx, const char *username);
int turn_setpassword (turn_t *restrict ctx, const char *password);

int turn_connect (turn_t *restrict ctx, const struct sockaddr *restrict dst,
                  socklen_t len);

ssize_t turn_sendto (turn_t *restrict ctx, const void *data, size_t datalen,
                     int flags, const struct sockaddr *restrict dst,
                     socklen_t dstlen);
ssize_t turn_send (turn_t *restrict ctx, const void *data, size_t len,
                   int flags);

ssize_t turn_recvfrom (turn_t *restrict ctx, void *data, size_t len, int flags,
                       const struct sockaddr *restrict src, socklen_t *srclen);
ssize_t turn_recv (turn_t *restrict ctx, void *data, size_t len, int flags);

int turn_getsockname (turn_t *restrict ctx,
                      const struct sockaddr *restrict name, socklen_t *len);
int turn_getpeername (turn_t *restrict ctx,
                      const struct sockaddr *restrict name, socklen_t *len);

int turn_close (turn_t *ctx);

# ifdef __cplusplus
}
# endif

#endif
