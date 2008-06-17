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

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#ifdef HAVE_POLL
# include <poll.h>
#endif

#include "stun/stunagent.h"
#include "trans.h"

#define TRANS_OWN_FD   0x1 /* descriptor belongs to us */
#define TRANS_RELIABLE 0x2 /* reliable transport */
#define TRANS_FGPRINT  0x4 /* whether to use FINGERPRINT */

int stun_trans_init (stun_trans_t *restrict tr, int fd,
                     const struct sockaddr *restrict srv, socklen_t srvlen)
{
  int sotype;
  socklen_t solen = sizeof (sotype);

  assert (fd != -1);

  if (srvlen > sizeof (tr->sock.dst))
    return ENOBUFS;

  tr->flags = 0;
  tr->msg.offset = 0;
  tr->sock.fd = fd;
  memcpy (&tr->sock.dst, srv, tr->sock.dstlen = srvlen);
  tr->key.length = 0;
  tr->key.value = NULL;

  assert (getsockopt (fd, SOL_SOCKET, SO_TYPE, &sotype, &solen) == 0);
  (void)getsockopt (fd, SOL_SOCKET, SO_TYPE, &sotype, &solen);

  switch (sotype)
  {
    case SOCK_STREAM:
    case SOCK_SEQPACKET:
      tr->flags |= TRANS_RELIABLE;
  }

  return 0;
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


int stun_trans_create (stun_trans_t *restrict tr, int type, int proto,
                       const struct sockaddr *restrict srv, socklen_t srvlen)
{
  int val, fd;

  if (srvlen < sizeof(*srv))
    return EINVAL;

  fd = stun_socket (srv->sa_family, type, proto);
  if (fd == -1)
    return errno;

  if (connect (fd, srv, srvlen) && (errno != EINPROGRESS))
  {
    val = errno;
    goto error;
  }

  val = stun_trans_init (tr, fd, NULL, 0);
  if (val)
    goto error;

  tr->flags |= TRANS_OWN_FD;
  return 0;

error:
  close (fd);
  return val;
}


void stun_trans_deinit (stun_trans_t *tr)
{
  int saved = errno;

  assert (tr->sock.fd != -1);

  if (tr->flags & TRANS_OWN_FD)
    close (tr->sock.fd);
  free (tr->key.value);

#ifndef NDEBUG
  tr->sock.fd = -1;
#endif
  errno = saved;
}


#ifndef MSG_DONTWAIT
# define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif


static int stun_trans_send (stun_trans_t *tr);

int stun_trans_start (stun_trans_t *tr)
{
  int val;

  tr->msg.offset = 0;

  if (tr->flags & TRANS_RELIABLE)
    /*
     * FIXME: wait for three-way handshake, somewhere
     */
    stun_timer_start_reliable (&tr->timer);
  else
    stun_timer_start (&tr->timer);

  stun_debug ("STUN transaction @%p started (timeout: %ums)\n", tr,
       stun_trans_timeout (tr));

  val = stun_trans_send (tr);
  if (val)
    return val;

  return 0;
}


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


ssize_t stun_sendto (int fd, const uint8_t *buf, size_t len,
                     const struct sockaddr *dst, socklen_t dstlen)
{
  static const int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
  ssize_t val;

  do
  {
    if (dstlen > 0)
      val = sendto (fd, buf, len, flags, dst, dstlen);
    else
      val = send (fd, buf, len, flags);
  }
  while ((val == -1) && stun_err_dequeue (fd));

  return val;
}


ssize_t stun_recvfrom (int fd, uint8_t *buf, size_t maxlen,
                       struct sockaddr *restrict dst,
                       socklen_t *restrict dstlen)
{
  static const int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
  ssize_t val;

  if (dstlen != NULL)
    val = recvfrom (fd, buf, maxlen, flags, dst, dstlen);
  else
    val = recv (fd, buf, maxlen, flags);

  if ((val == -1) && stun_err_dequeue (fd))
    errno = EAGAIN;

  return val;
}


unsigned stun_trans_timeout (const stun_trans_t *tr)
{
  assert (tr != NULL);
  assert (tr->sock.fd != -1);
  return stun_timer_remainder (&tr->timer);
}


int stun_trans_fd (const stun_trans_t *tr)
{
  assert (tr != NULL);
  assert (tr->sock.fd != -1);
  return tr->sock.fd;
}


bool stun_trans_reading (const stun_trans_t *tr)
{
  (void)tr;
  return true;
}


bool stun_trans_writing (const stun_trans_t *tr)
{
  (void)tr;
  return false;
}


/**
 * Try to send STUN request/indication
 */
static int
stun_trans_send (stun_trans_t *tr)
{
  const uint8_t *data = tr->msg.buf + tr->msg.offset;
  size_t len = tr->msg.length - tr->msg.offset;
  ssize_t val;

  val = stun_sendto (tr->sock.fd, data, len,
                     (struct sockaddr *)&tr->sock.dst, tr->sock.dstlen);
  if (val < 0)
    return errno;

  /* Message sent succesfully! */
  tr->msg.offset += val;
  assert (tr->msg.offset <= tr->msg.length);

  return 0;
}


int stun_trans_tick (stun_trans_t *tr)
{
  assert (tr->sock.fd != -1);

  switch (stun_timer_refresh (&tr->timer))
  {
    case -1:
      stun_debug ("STUN transaction @%p failed: time out.\n", tr);
      return ETIMEDOUT; // fatal error!

    case 0:
      /* Retransmit can only happen with non reliable transport */
      assert ((tr->flags & TRANS_RELIABLE) == 0);
      tr->msg.offset = 0;

      stun_trans_send (tr);
      stun_debug ("STUN transaction @%p retransmitted (timeout: %ums).\n", tr,
           stun_trans_timeout (tr));
  }
  return EAGAIN;
}


/**
 * Waits for a response or timeout to occur.
 *
 * @return ETIMEDOUT if the transaction has timed out, or 0 if an incoming
 * message needs to be processed.
 */
static int stun_trans_wait (stun_trans_t *tr)
{
#ifdef HAVE_POLL
  int val = 0;

  do
  {
    struct pollfd ufd;
    unsigned delay = stun_trans_timeout (tr);

    memset (&ufd, 0, sizeof (ufd));
    ufd.fd = stun_trans_fd (tr);

    if (stun_trans_writing (tr))
      ufd.events |= POLLOUT;
    if (stun_trans_reading (tr))
      ufd.events |= POLLIN;

    if (poll (&ufd, 1, delay) <= 0)
    {
      val = stun_trans_tick (tr);
      continue;
    }

    val = 0;
  }
  while (val == EAGAIN);

  return val;
#else
  (void)tr;
  return ENOSYS;
#endif
}


int stun_trans_recv (stun_trans_t *tr, uint8_t *buf, size_t buflen)
{
  for (;;)
  {
    ssize_t val = stun_trans_wait (tr);
    if (val)
    {
      errno = val /* = ETIMEDOUT */;
      return -1;
    }

    val = stun_recv (tr->sock.fd, buf, buflen);
    if (val >= 0)
      return val;
  }
}



int stun_trans_preprocess (StunAgent *agent,
    stun_trans_t *restrict tr, int *pcode,
    const void *restrict buf, size_t len)
{
  StunValidationStatus valid;

  assert (pcode != NULL);

  *pcode = -1;

  valid = stun_agent_validate (agent, &tr->message, buf, len, NULL, NULL);
  if (valid == STUN_VALIDATION_UNKNOWN_ATTRIBUTE)
    return EPROTO;

  if (valid != STUN_VALIDATION_SUCCESS)
    return EAGAIN;

  switch (stun_message_get_class (&tr->message))
  {
    case STUN_REQUEST:
    case STUN_INDICATION:
      return EAGAIN;
      break;

    case STUN_ERROR:
      if (stun_message_find_error (&tr->message, pcode) != 0)
        return EAGAIN; // missing ERROR-CODE: ignore message
      break;
  }

  stun_debug ("Received %u-bytes STUN message\n", (unsigned)len);
  /* NOTE: currently we ignore unauthenticated messages if the context
   * is authenticated, for security reasons. */
  if (*pcode >= 0)
  {
    stun_debug (" STUN error message received (code: %d)\n", *pcode);

    /* ALTERNATE-SERVER mechanism */
    if ((tr->key.value != NULL) && ((*pcode / 100) == 3))
    {
      struct sockaddr_storage srv;
      socklen_t slen = sizeof (srv);

      if (stun_message_find_addr (&tr->message, STUN_ATTRIBUTE_ALTERNATE_SERVER,
                          (struct sockaddr *)&srv, &slen))
      {
        stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute\n");
        return ECONNREFUSED;
      }

      if (tr->sock.dstlen == 0)
      {
        if (connect (tr->sock.fd, (struct sockaddr *)&srv, slen))
        {
          /* This error case includes address family mismatch */
          stun_debug (" Error switching to alternate server: %s\n",
               strerror (errno));
          return ECONNREFUSED;
        }
      }
      else
      {
        if ((tr->sock.dst.ss_family != srv.ss_family)
         || (slen > sizeof (tr->sock.dst)))
        {
          stun_debug (" Unsupported alternate server\n");
          return ECONNREFUSED;
        }

        memcpy (&tr->sock.dst, &srv, tr->sock.dstlen = slen);
      }

      stun_debug (" Restarting with alternate server\n");
      if (stun_trans_start (tr) == 0)
        return EAGAIN;

      stun_debug (" Restart failed!\n");
    }

    return ECONNREFUSED;
  }

  return 0;
}


ssize_t stun_send (int fd, const uint8_t *buf, size_t len)
{
  return stun_sendto (fd, buf, len, NULL, 0);
}

ssize_t stun_recv (int fd, uint8_t *buf, size_t maxlen)
{
  return stun_recvfrom (fd, buf, maxlen, NULL, NULL);
}
