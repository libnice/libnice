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

#ifndef STUN_TRANS_H
# define STUN_TRANS_H 1

/**
 * @file trans.h
 * @brief STUN client generic transaction layer
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "win32_common.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#endif

#include <sys/types.h>


typedef struct stun_trans_s
{

  int fd;
  int own_fd;
  socklen_t dstlen;
  struct sockaddr_storage dst;
} stun_trans_t;


# ifdef __cplusplus
extern "C" {
# endif

/**
 * Initializes a new STUN request transaction
 *
 * @param tr pointer to an unused STUN transaction struct
 * @param fd socket descriptor to use
 * @param srv STUN server socket address (ignored if @a srvlen is 0)
 * @param srvlen STUN server socket address length (or 0 @a fd is connected)
 */
int stun_trans_init (stun_trans_t *tr, int fd,
                     const struct sockaddr *srv, socklen_t srvlen);

/**
 * Initializes a new STUN request transaction with its dedicated socket
 *
 * @param tr pointer to an unused STUN transaction struct
 * @param sotype socket type (as in socket() second parameter)
 * @param proto socket protocol (as in socket() third parameter)
 * @param srv STUN server socket address (ignored if @a srvlen is 0)
 * @param srvlen STUN server socket address length (or 0 @a fd is connected)
 */
int stun_trans_create (stun_trans_t *tr, int sotype, int proto,
                       const struct sockaddr *srv, socklen_t srvlen);

/**
 * Releases resources allocated by stun_trans_init() or stun_trans_create(),
 * and cancel the transaction if still pending.
 */
void stun_trans_deinit (stun_trans_t *tr);

/**
 * This is meant to integrate with I/O polling loops and event frameworks.
 *
 * @return file descriptor the transaction is waiting for.
 * Always succeeds.
 */
int stun_trans_fd (const stun_trans_t *tr);
int stun_trans_poll (stun_trans_t *tr, unsigned int delay);

/**
 * Safe wrapper around sendto()
 * - returns EPIPE, but never yields SIGPIPE.
 * - non blocking regardless of file descriptor blocking-ness.
 * - drops incoming ICMP errors. FIXME: this is actually quite bad;
 *   we should process ICMP errors, not ignore them.
 *
 * This can be used to send non-requests message, i.e. whenever the
 * transaction is not used.
 */
ssize_t stun_trans_sendto (stun_trans_t *tr, const uint8_t *buf, size_t len,
                     const struct sockaddr *dst, socklen_t dstlen);

ssize_t stun_trans_recvfrom (stun_trans_t *tr, uint8_t *buf, size_t maxlen,
                       struct sockaddr *src,
                       socklen_t *srclen);

ssize_t stun_trans_send (stun_trans_t *tr, const uint8_t *buf, size_t len);

ssize_t stun_trans_recv (stun_trans_t *tr, uint8_t *buf, size_t maxlen);

# ifdef __cplusplus
}
# endif

#endif /* !STUN_TRANS_H */
