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

#ifndef STUN_BIND_H
# define STUN_BIND_H 1

/**
 * @file bind.h
 * @brief STUN binding discovery
 */

# ifndef IPPORT_STUN
/** Default port for STUN binding discovery */
#  define IPPORT_STUN  3478
# endif

typedef struct stun_bind_s stun_bind_t;
# include <stdbool.h>
# include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Performs STUN Binding discovery in blocking mode.
 *
 * @param fd socket to use for binding discovery, or -1 to create one
 * @param srv STUN server socket address
 * @param srvlen STUN server socket address byte length
 * @param addr [OUT] pointer to a socket address structure to hold 
 * discovered binding (Remember that it can be an IPv6 even if the socket
 * local family is IPv4, so you should use a sockaddr_storage buffer)
 * @param addrlen [IN/OUT] pointer to the byte length of addr, set to the byte
 * length of the binding socket address on return.
 *
 * @return 0 on success, a standard error value in case of error.
 * In case of error, addr and addrlen are undefined.
 */
int stun_bind_run (int fd,
                   const struct sockaddr *restrict srv, socklen_t srvlen,
                   struct sockaddr *restrict addr, socklen_t *addrlen);

/**
 * Starts STUN Binding discovery in non-blocking mode.
 *
 * @param context pointer to an opaque pointer that will be passed to
 * other stun_bind_*() functions afterward
 * @param fd socket to use for discovery, or -1 to create one
 * @param srv STUN server socket address
 * @param srvlen STUN server socket address length
 *
 * @return 0 on success, a standard error value otherwise.
 */
int stun_bind_start (stun_bind_t **restrict context, int fd,
                     const struct sockaddr *restrict srv, socklen_t srvlen);

/**
 * Aborts a running STUN Binding discovery.
 * @param context binding discovery (or conncheck) context pointer
 * to be released.
 */
void stun_bind_cancel (stun_bind_t *context);

/**
 * This is meant to integrate with I/O pooling loops and event frameworks.
 *
 * @param context binding discovery (or conncheck) context pointer
 * @return recommended maximum delay (in milliseconds) to wait for a
 * response.
 */
unsigned stun_bind_timeout (const stun_bind_t *context);

/**
 * Handles retransmission timeout, and sends request retransmit if needed.
 * This should be called whenever event polling indicates that
 * stun_bind_timeout() has elapsed. It is however safe to call this earlier
 * (in which case retransmission will not occur) or later (in which case
 * late retransmission will be done).
 *
 * @param context binding discovery (or conncheck) context pointer
 *
 * @return ETIMEDOUT if the transaction has timed out, or EAGAIN if it is
 * still pending.
 *
 * If anything except EAGAIN (but including zero) is returned, the context
 * is free'd and must no longer be used.
 */
int stun_bind_elapse (stun_bind_t *context);

/**
 * Gives data to be processed within the context of a STUN Binding discovery
 * or ICE connectivity check.
 *
 * @param context context (from stun_bind_start() or stun_conncheck_start())
 * @param buf pointer to received data to be processed
 * @param len byte length of data at @a buf
 * @param addr socket address pointer to receive mapped address in case of
 * successful processing
 * @param addrlen [IN/OUT] pointer to the size of the socket address buffer
 * at @a addr upon entry, set to the useful size on success
 *
 * @return 0 on success, an error code otherwise:
 * - EAGAIN: ignored invalid message (non-fatal error)
 * - ECONNRESET: role conflict error from server
 * - ECONNREFUSED: any other fatal error message from server
 * - EPROTO: unsupported message from server
 * - ENOENT: no mapped address in message from server
 * - EAFNOSUPPORT: unsupported mapped address family from server
 * - EINVAL: invalid mapped address from server
 *
 * If anything except EAGAIN (but including zero) is returned, the context
 * is free'd and must no longer be used.
 */
int stun_bind_process (stun_bind_t *restrict context,
                       const void *restrict buf, size_t len,
                       struct sockaddr *restrict addr, socklen_t *addrlen);

/**
 * Sends a STUN Binding indication, aka ICE keep-alive packet.
 *
 * @param fd socket descriptor to send packet through
 * @param srv destination socket address (possibly NULL if connected)
 * @param srvlen destination socket address length (possibly 0)
 * @return 0 on success, an error code from sendto() otherwise.
 */
int stun_bind_keepalive (int fd, const struct sockaddr *restrict srv,
                         socklen_t srvlen);


/**
 * <b>Provisional</b> and incomplete STUN NAT control API
 * Subject to change.
 */
typedef struct stun_nested_s stun_nested_t;

int stun_nested_start (stun_nested_t **restrict context, int fd,
                       const struct sockaddr *restrict mapad,
                       const struct sockaddr *restrict natad,
                       socklen_t adlen, uint32_t refresh);

int stun_nested_process (stun_nested_t *restrict ctx,
                         const void *restrict buf, size_t len,
                         struct sockaddr *restrict intad, socklen_t *adlen);


# ifndef STUN_VALIDATE_DECLARATION
#  define STUN_VALIDATE_DECLARATION 2
ssize_t stun_validate (const uint8_t *msg, size_t len);
# endif

# ifdef __cplusplus
}
# endif

#endif
