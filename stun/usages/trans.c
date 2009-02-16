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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>


#ifdef _WIN32
#define close closesocket
#else
#include <errno.h>
#include <unistd.h>
#endif


#ifdef HAVE_POLL
# include <poll.h>
#endif

#include "trans.h"

StunUsageTransReturn stun_trans_init (StunTransport *tr, int fd,
                     const struct sockaddr *srv, socklen_t srvlen)
{
  assert (fd != -1);

  if ((size_t) srvlen > sizeof (tr->dst))
    return STUN_USAGE_TRANS_RETURN_INVALID_ADDRESS;

  tr->own_fd = -1;
  tr->fd = fd;

  tr->dstlen = srvlen;
  memcpy (&tr->dst, srv, srvlen);

  return STUN_USAGE_TRANS_RETURN_SUCCESS;
}


/**
 * Creates and connects a socket. This is useful when a socket is to be used
 * for multiple consecutive transactions (e.g. TURN).
 */
static int stun_socket (int family, int type, int proto)
{
  int fd = socket (family, type, proto);
  if (fd == -1)
    return -1;

#ifdef FD_CLOEXEC
  fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
  fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
#endif

#ifdef MSG_ERRQUEUE
  if (type == SOCK_DGRAM)
  {
    /* Linux specifics for ICMP errors on non-connected sockets */
    int yes = 1;
    switch (family)
    {
      case AF_INET:
        setsockopt (fd, SOL_IP, IP_RECVERR, &yes, sizeof (yes));
        break;
      case AF_INET6:
        setsockopt (fd, SOL_IPV6, IPV6_RECVERR, &yes, sizeof (yes));
        break;
    }
  }
#endif

  return fd;
}


StunUsageTransReturn stun_trans_create (StunTransport *tr, int type, int proto,
                       const struct sockaddr *srv, socklen_t srvlen)
{
  StunUsageTransReturn val = STUN_USAGE_TRANS_RETURN_ERROR;
  int fd;

  if ((size_t) srvlen < sizeof(*srv))
    return STUN_USAGE_TRANS_RETURN_INVALID_ADDRESS;

  fd = stun_socket (srv->sa_family, type, proto);
  if (fd == -1)
    return STUN_USAGE_TRANS_RETURN_ERROR;

  if (connect (fd, srv, srvlen) &&
#ifdef _WIN32
      (WSAGetLastError () != WSAEINPROGRESS)) {
#else
    (errno != EINPROGRESS)) {
#endif
    goto error;
  }

  val = stun_trans_init (tr, fd, NULL, 0);
  if (val)
    goto error;

  tr->own_fd = tr->fd;
  return STUN_USAGE_TRANS_RETURN_SUCCESS;

error:
  close (fd);
  return val;
}


void stun_trans_deinit (StunTransport *tr)
{
  int saved = errno;

  assert (tr->fd != -1);

  if (tr->own_fd != -1)
    close (tr->own_fd);

  tr->own_fd = -1;
  tr->fd = -1;

  errno = saved;
}


#ifndef MSG_DONTWAIT
# define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif


static int stun_err_dequeue (int fd)
{
#ifdef MSG_ERRQUEUE
  struct msghdr hdr;
  int saved_errno = errno, ret;

  memset (&hdr, 0, sizeof (hdr));
  ret = (recvmsg (fd, &hdr, MSG_ERRQUEUE) >= 0);
  errno = saved_errno;
  return ret;
#else
  return 0;
#endif
}


ssize_t stun_trans_send (StunTransport *tr, const uint8_t *buf, size_t len)
{
  return stun_trans_sendto (tr, buf, len,
      (struct sockaddr *)&tr->dst, tr->dstlen);
}

ssize_t stun_trans_recv (StunTransport *tr, uint8_t *buf, size_t maxlen)
{
  return stun_trans_recvfrom (tr, buf, maxlen, NULL, NULL);
}


ssize_t stun_trans_sendto (StunTransport *tr, const uint8_t *buf, size_t len,
                     const struct sockaddr *dst, socklen_t dstlen)
{
  static const int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
  ssize_t val;

  do
  {
    if (dstlen > 0)
      val = sendto (tr->fd, (void *)buf, len, flags, dst, dstlen);
    else
      val = send (tr->fd, (void *)buf, len, flags);
  }
  while ((val == -1) && stun_err_dequeue (tr->fd));

  return val;
}


ssize_t stun_trans_recvfrom (StunTransport *tr, uint8_t *buf, size_t maxlen,
                       struct sockaddr * dst,
                       socklen_t * dstlen)
{
  static const int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
  ssize_t val;

  if (dstlen != NULL)
    val = recvfrom (tr->fd, (void *)buf, maxlen, flags, dst, dstlen);
  else
    val = recv (tr->fd, (void *)buf, maxlen, flags);

  if (val == -1)
    stun_err_dequeue (tr->fd);

  return val;
}



int stun_trans_fd (const StunTransport *tr)
{
  assert (tr != NULL);
  return tr->fd;
}


/**
 * Waits for a response or timeout to occur.
 *
 * @return ETIMEDOUT if the transaction has timed out, or 0 if an incoming
 * message needs to be processed.
 */
StunUsageTransReturn stun_trans_poll (StunTransport *tr, unsigned int delay)
{
#ifdef HAVE_POLL
  struct pollfd ufd;

  memset (&ufd, 0, sizeof (ufd));
  ufd.fd = stun_trans_fd (tr);

  ufd.events |= POLLIN;

  if (poll (&ufd, 1, delay) <= 0) {
    return STUN_USAGE_TRANS_RETURN_RETRY;
  }

  return STUN_USAGE_TRANS_RETURN_SUCCESS;
#else
  (void)tr;
  return STUN_USAGE_TRANS_RETURN_UNSUPPORTED;
#endif
}
