/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007-2009 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include "win32_common.h"
#define close closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#endif


#ifdef HAVE_POLL
# include <poll.h>
#endif


#include "bind.h"
#include "stun/stunagent.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include "timer.h"


#ifndef SOL_IP
# define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif


/** Non-blocking mode STUN binding discovery */

size_t stun_usage_bind_create (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len)
{
  stun_agent_init_request (agent, msg, buffer, buffer_len, STUN_BINDING);

  return stun_agent_finish_message (agent, msg, NULL, 0);
}

StunUsageBindReturn stun_usage_bind_process (StunMessage *msg,
    struct sockaddr *addr, socklen_t *addrlen,
    struct sockaddr *alternate_server, socklen_t *alternate_server_len)
{
  int code = -1;
  StunMessageReturn val;

  if (stun_message_get_method (msg) != STUN_BINDING)
    return STUN_USAGE_BIND_RETURN_INVALID;

  switch (stun_message_get_class (msg))
  {
    case STUN_REQUEST:
    case STUN_INDICATION:
      return STUN_USAGE_BIND_RETURN_INVALID;

    case STUN_RESPONSE:
      break;

    case STUN_ERROR:
      if (stun_message_find_error (msg, &code) != STUN_MESSAGE_RETURN_SUCCESS) {
        /* missing ERROR-CODE: ignore message */
        return STUN_USAGE_BIND_RETURN_INVALID;
      }

      /* NOTE: currently we ignore unauthenticated messages if the context
       * is authenticated, for security reasons. */
      stun_debug (" STUN error message received (code: %d)", code);

      /* ALTERNATE-SERVER mechanism */
      if ((code / 100) == 3) {
        if (alternate_server && alternate_server_len) {
          if (stun_message_find_addr (msg, STUN_ATTRIBUTE_ALTERNATE_SERVER,
                  (struct sockaddr_storage *) alternate_server,
                  alternate_server_len) != STUN_MESSAGE_RETURN_SUCCESS) {
            stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute");
            return STUN_USAGE_BIND_RETURN_ERROR;
          }
        } else {
          if (!stun_message_has_attribute (msg, STUN_ATTRIBUTE_ALTERNATE_SERVER)) {
            stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute");
            return STUN_USAGE_BIND_RETURN_ERROR;
          }
        }

        stun_debug ("Found alternate server");
        return STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER;

      }
      return STUN_USAGE_BIND_RETURN_ERROR;

    default:
      /* Fall through. */
      break;
  }

  stun_debug ("Received %u-bytes STUN message", stun_message_length (msg));

  val = stun_message_find_xor_addr (msg,
      STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr_storage *)addr,
      addrlen);
  if (val != STUN_MESSAGE_RETURN_SUCCESS)
  {
    stun_debug (" No XOR-MAPPED-ADDRESS: %d", val);
    val = stun_message_find_addr (msg,
        STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr_storage *)addr,
        addrlen);
    if (val != STUN_MESSAGE_RETURN_SUCCESS)
    {
      stun_debug (" No MAPPED-ADDRESS: %d", val);
      return STUN_USAGE_BIND_RETURN_ERROR;
    }
  }

  stun_debug (" Mapped address found!");
  return STUN_USAGE_BIND_RETURN_SUCCESS;

}


/** Binding keep-alive (Binding discovery indication!) */

size_t
stun_usage_bind_keepalive (StunAgent *agent, StunMessage *msg,
    uint8_t *buf, size_t len)
{

  stun_agent_init_indication (agent, msg,
      buf, len, STUN_BINDING);
  return stun_agent_finish_message (agent, msg, NULL, 0);
}



typedef struct stun_trans_s
{

  int fd;
  int own_fd;
  socklen_t dstlen;
  struct sockaddr_storage dst;
} StunTransport;


typedef enum {
  STUN_USAGE_TRANS_RETURN_SUCCESS,
  STUN_USAGE_TRANS_RETURN_ERROR,
  STUN_USAGE_TRANS_RETURN_RETRY,
  STUN_USAGE_TRANS_RETURN_INVALID_ADDRESS,
  STUN_USAGE_TRANS_RETURN_UNSUPPORTED,
} StunUsageTransReturn;




static StunUsageTransReturn
stun_trans_init (StunTransport *tr, int fd,
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


/*
 * Creates and connects a socket. This is useful when a socket is to be used
 * for multiple consecutive transactions (e.g. TURN).
 */
static int stun_socket (int family, int type, int proto)
{
#ifdef _WIN32
  unsigned long set_nonblock=1;
#endif

  int fd = socket (family, type, proto);
  if (fd == -1)
    return -1;

#ifdef FD_CLOEXEC
  fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
  fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK);
#elif defined _WIN32
  ioctlsocket(fd, FIONBIO, &set_nonblock);
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
      default:
        /* Nothing to do. */
        break;
    }
  }
#endif

  return fd;
}


static StunUsageTransReturn
stun_trans_create (StunTransport *tr, int type, int proto,
    const struct sockaddr *srv, socklen_t srvlen)
{
  StunUsageTransReturn val = STUN_USAGE_TRANS_RETURN_ERROR;
  int fd;

  if ((size_t) srvlen < sizeof(*srv))
    return STUN_USAGE_TRANS_RETURN_INVALID_ADDRESS;

  fd = stun_socket (srv->sa_family, type, proto);
  if (fd == -1)
    return STUN_USAGE_TRANS_RETURN_ERROR;

  if (type != SOCK_DGRAM) {
    if (connect (fd, srv, srvlen) &&
#ifdef _WIN32
        (WSAGetLastError () != WSAEINPROGRESS)) {
#else
      (errno != EINPROGRESS)) {
#endif
      goto error;
    }
    val = stun_trans_init (tr, fd, NULL, 0);
  } else {
    val = stun_trans_init (tr, fd, srv, srvlen);
  }

  if (val)
    goto error;

  tr->own_fd = tr->fd;
  return STUN_USAGE_TRANS_RETURN_SUCCESS;

error:
  close (fd);
  return val;
}


static void stun_trans_deinit (StunTransport *tr)
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
  (void) fd;
  return 0;
#endif
}


static ssize_t
stun_trans_sendto (StunTransport *tr, const uint8_t *buf, size_t len,
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


static ssize_t
stun_trans_recvfrom (StunTransport *tr, uint8_t *buf, size_t maxlen,
                       struct sockaddr_storage * dst,
                       socklen_t * dstlen)
{
  static const int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
  ssize_t val;

  if (dstlen != NULL)
    val = recvfrom (tr->fd, (void *)buf, maxlen, flags, (struct sockaddr *) dst,
        dstlen);
  else
    val = recv (tr->fd, (void *)buf, maxlen, flags);

  if (val == -1)
    stun_err_dequeue (tr->fd);

  return val;
}


static ssize_t
stun_trans_send (StunTransport *tr, const uint8_t *buf, size_t len)
{
  struct sockaddr *conv;

  conv = (struct sockaddr *) &tr->dst;

  return stun_trans_sendto (tr, buf, len, conv, tr->dstlen);
}

static ssize_t
stun_trans_recv (StunTransport *tr, uint8_t *buf, size_t maxlen)
{
  return stun_trans_recvfrom (tr, buf, maxlen, NULL, NULL);
}


#ifdef HAVE_POLL
static int stun_trans_fd (const StunTransport *tr)
{
  assert (tr != NULL);
  return tr->fd;
}
#endif


/*
 * Waits for a response or timeout to occur.
 *
 * @return ETIMEDOUT if the transaction has timed out, or 0 if an incoming
 * message needs to be processed.
 */
static StunUsageTransReturn
stun_trans_poll (StunTransport *tr, unsigned int delay)
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



/** Blocking mode STUN binding discovery */
StunUsageBindReturn stun_usage_bind_run (const struct sockaddr *srv,
    socklen_t srvlen, struct sockaddr_storage *addr, socklen_t *addrlen)
{
  StunTimer timer;
  StunTransport trans;
  StunAgent agent;
  StunMessage req;
  uint8_t req_buf[STUN_MAX_MESSAGE_SIZE];
  StunMessage msg;
  uint8_t buf[STUN_MAX_MESSAGE_SIZE];
  StunValidationStatus valid;
  size_t len;
  StunUsageTransReturn ret;
  int val;
  struct sockaddr_storage alternate_server;
  socklen_t alternate_server_len = sizeof (alternate_server);
  StunUsageBindReturn bind_ret;

  stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC3489, 0);

  len = stun_usage_bind_create (&agent, &req, req_buf, sizeof(req_buf));

  ret = stun_trans_create (&trans, SOCK_DGRAM, 0, srv, srvlen);
  if (ret != STUN_USAGE_TRANS_RETURN_SUCCESS) {
    stun_debug ("STUN transaction failed: couldn't create transport.");
    return STUN_USAGE_BIND_RETURN_ERROR;
  }

  val = stun_trans_send (&trans, req_buf, len);
  if (val < -1) {
    stun_debug ("STUN transaction failed: couldn't send request.");
    return STUN_USAGE_BIND_RETURN_ERROR;
  }

  stun_timer_start (&timer, STUN_TIMER_DEFAULT_TIMEOUT,
      STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
  stun_debug ("STUN transaction started (timeout %dms).",
      stun_timer_remainder (&timer));

  do
  {
    for (;;) {
      unsigned delay = stun_timer_remainder (&timer);
      ret = stun_trans_poll (&trans, delay);
      if (ret == STUN_USAGE_TRANS_RETURN_RETRY) {
        switch (stun_timer_refresh (&timer)) {
          case STUN_USAGE_TIMER_RETURN_TIMEOUT:
            stun_debug ("STUN transaction failed: time out.");
            return STUN_USAGE_BIND_RETURN_TIMEOUT; // fatal error!
          case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
            stun_debug ("STUN transaction retransmitted (timeout %dms).",
                stun_timer_remainder (&timer));
            val = stun_trans_send (&trans, req_buf, len);
            if (val <  -1) {
              stun_debug ("STUN transaction failed: couldn't resend request.");
              return STUN_USAGE_BIND_RETURN_ERROR;
            }
            continue;
          case STUN_USAGE_TIMER_RETURN_SUCCESS:
          default:
            /* Fall through. */
            break;
        }
      }
      val = stun_trans_recv (&trans, buf, sizeof (buf));
      if (val >= 0) {
        break;
      }
    }

    valid = stun_agent_validate (&agent, &msg, buf, val, NULL, NULL);
    if (valid == STUN_VALIDATION_UNKNOWN_ATTRIBUTE)
      return STUN_USAGE_BIND_RETURN_ERROR;

    if (valid != STUN_VALIDATION_SUCCESS) {
      ret = STUN_USAGE_TRANS_RETURN_RETRY;
    } else {
      bind_ret = stun_usage_bind_process (&msg, (struct sockaddr *)  addr,
          addrlen, (struct sockaddr *) &alternate_server, &alternate_server_len);
      if (bind_ret == STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER) {
        stun_trans_deinit (&trans);

        ret = stun_trans_create (&trans, SOCK_DGRAM, 0,
            (struct sockaddr *) &alternate_server, alternate_server_len);

        if (ret != STUN_USAGE_TRANS_RETURN_SUCCESS) {
          return STUN_USAGE_BIND_RETURN_ERROR;
        }

        val = stun_trans_send (&trans, req_buf, len);
        if (val < -1)
          return STUN_USAGE_BIND_RETURN_ERROR;

        stun_timer_start (&timer, STUN_TIMER_DEFAULT_TIMEOUT,
            STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
        ret = STUN_USAGE_TRANS_RETURN_RETRY;
      } else if (bind_ret ==  STUN_USAGE_BIND_RETURN_INVALID) {
        ret = STUN_USAGE_TRANS_RETURN_RETRY;
      } else {
        break;
      }
    }
  }
  while (ret == STUN_USAGE_TRANS_RETURN_RETRY);

  return bind_ret;
}
