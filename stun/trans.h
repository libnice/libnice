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

# include <sys/types.h>
# include <sys/socket.h>

# include "timer.h"

typedef struct stun_trans_s
{
	stun_timer_t timer;
	unsigned  flags;

	struct
	{
		size_t  length, offset;
		uint8_t buf[STUN_MAXMSG];
	} msg;

	struct
	{
		int                     fd;
		socklen_t               dstlen;
		struct sockaddr_storage dst;
	} sock;

	struct
	{
		size_t  length;
		uint8_t *value;
	} key;
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
int stun_trans_init (stun_trans_t *restrict tr, int fd,
                     const struct sockaddr *restrict srv, socklen_t srvlen);

/**
 * Initializes a new STUN request transaction with its dedicated socket
 *
 * @param tr pointer to an unused STUN transaction struct
 * @param sotype socket type (as in socket() second parameter)
 * @param proto socket protocol (as is socket() third parameter)
 * @param srv STUN server socket address (ignored if @a srvlen is 0)
 * @param srvlen STUN server socket address length (or 0 @a fd is connected)
 */
int stun_trans_create (stun_trans_t *restrict tr, int sotype, int proto,
                       const struct sockaddr *restrict srv, socklen_t srvlen);

void stun_trans_deinit (stun_trans_t *restrict tr);

int stun_trans_start (stun_trans_t *restrict tr);
int stun_trans_tick (stun_trans_t *tr);
int stun_trans_preprocess (stun_trans_t *restrict tr, int *code,
                           const void *restrict buf, size_t len);

/**
 * This is meant to integrate with I/O pooling loops and event frameworks.
 *
 * @return recommended maximum delay (in milliseconds) to wait for a
 * response.
 */
unsigned stun_trans_timeout (const stun_trans_t *tr);

/**
 * This is meant to integrate with I/O polling loops and event frameworks.
 *
 * @return file descriptor used by the STUN Binding discovery context.
 * Always succeeds.
 */
int stun_trans_fd (const stun_trans_t *tr);

ssize_t stun_sendto (int fd, const uint8_t *buf, size_t len,
                     const struct sockaddr *dst, socklen_t dstlen);

# ifdef __cplusplus
}
# endif

#endif /* !STUN_TRANS_H */
