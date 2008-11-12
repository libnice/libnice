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

#ifdef _WIN32
#include <winsock2.h>
#include "win32_common.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#endif

#include "bind.h"
#include "stun/stunagent.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include "timer.h"
#include "trans.h"


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
  int val, code = -1;

  if (stun_message_get_method (msg) != STUN_BINDING)
    return STUN_USAGE_BIND_RETURN_RETRY;

  switch (stun_message_get_class (msg))
  {
    case STUN_REQUEST:
    case STUN_INDICATION:
      return STUN_USAGE_BIND_RETURN_RETRY;

    case STUN_RESPONSE:
      break;

    case STUN_ERROR:
      if (stun_message_find_error (msg, &code) != 0) {
        /* missing ERROR-CODE: ignore message */
        return STUN_USAGE_BIND_RETURN_RETRY;
      }

      /* NOTE: currently we ignore unauthenticated messages if the context
       * is authenticated, for security reasons. */
      stun_debug (" STUN error message received (code: %d)\n", code);

      /* ALTERNATE-SERVER mechanism */
      if ((code / 100) == 3) {
        if (alternate_server && alternate_server_len) {
          if (stun_message_find_addr (msg, STUN_ATTRIBUTE_ALTERNATE_SERVER,
                  alternate_server, alternate_server_len)) {
            stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute\n");
            return STUN_USAGE_BIND_RETURN_ERROR;
          }
        } else {
          if (!stun_message_has_attribute (msg, STUN_ATTRIBUTE_ALTERNATE_SERVER)) {
            stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute\n");
            return STUN_USAGE_BIND_RETURN_ERROR;
          }
        }

        stun_debug ("Found alternate server\n");
        return STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER;

      }
      return STUN_USAGE_BIND_RETURN_ERROR;
  }

  stun_debug ("Received %u-bytes STUN message\n", stun_message_length (msg));

  val = stun_message_find_xor_addr (msg,
      STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, addr, addrlen);
  if (val)
  {
    stun_debug (" No XOR-MAPPED-ADDRESS: %s\n", strerror (val));
    val = stun_message_find_addr (msg,
        STUN_ATTRIBUTE_MAPPED_ADDRESS, addr, addrlen);
    if (val)
    {
      stun_debug (" No MAPPED-ADDRESS: %s\n", strerror (val));
      return STUN_USAGE_BIND_RETURN_ERROR;
    }
  }

  stun_debug (" Mapped address found!\n");
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

/** Blocking mode STUN binding discovery */
StunUsageBindReturn stun_usage_bind_run (const struct sockaddr *srv,
    socklen_t srvlen, struct sockaddr *addr, socklen_t *addrlen)
{
  stun_timer_t timer;
  stun_trans_t trans;
  StunAgent agent;
  StunMessage req;
  uint8_t req_buf[STUN_MAX_MESSAGE_SIZE];
  StunMessage msg;
  uint8_t buf[STUN_MAX_MESSAGE_SIZE];
  StunValidationStatus valid;
  size_t len;
  ssize_t ret;
  int val;
  struct sockaddr_storage alternate_server;
  socklen_t alternate_server_len = sizeof (alternate_server);
  StunUsageBindReturn bind_ret;

  stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC3489, 0);

  len = stun_usage_bind_create (&agent, &req, req_buf, sizeof(req_buf));

  ret = stun_trans_create (&trans, SOCK_DGRAM, 0, srv, srvlen);
  if (ret) {
    errno = ret;
    stun_debug ("STUN transaction failed: couldn't create transport.\n");
    return STUN_USAGE_BIND_RETURN_ERROR;
  }

  val = stun_trans_send (&trans, req_buf, len);
  if (val < -1) {
    stun_debug ("STUN transaction failed: couldn't send request.\n");
    return STUN_USAGE_BIND_RETURN_ERROR;
  }

  stun_timer_start (&timer);
  stun_debug ("STUN transaction started (timeout %dms).\n",
      stun_timer_remainder (&timer));

  do
  {
    for (;;) {
      unsigned delay = stun_timer_remainder (&timer);
      ret = stun_trans_poll (&trans, delay);
      if (ret == EAGAIN) {
        switch (stun_timer_refresh (&timer)) {
          case -1:
            stun_debug ("STUN transaction failed: time out.\n");
            return STUN_USAGE_BIND_RETURN_TIMEOUT; // fatal error!
          case 0:
            stun_debug ("STUN transaction retransmitted (timeout %dms).\n",
                stun_timer_remainder (&timer));
            val = stun_trans_send (&trans, req_buf, len);
            if (val <  -1) {
              stun_debug ("STUN transaction failed: couldn't resend request.\n");
              return STUN_USAGE_BIND_RETURN_ERROR;
            }
            ret = EAGAIN;
            continue;
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
      ret = EAGAIN;
    } else {
      bind_ret = stun_usage_bind_process (&msg, addr, addrlen,
          (struct sockaddr *) &alternate_server, &alternate_server_len);
      if (bind_ret == STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER) {
        stun_trans_deinit (&trans);

        ret = stun_trans_create (&trans, SOCK_DGRAM, 0,
            (struct sockaddr *) &alternate_server, alternate_server_len);

        if (ret) {
          errno = ret;
          return STUN_USAGE_BIND_RETURN_ERROR;
        }

        val = stun_trans_send (&trans, req_buf, len);
        if (val < -1)
          return STUN_USAGE_BIND_RETURN_ERROR;

        stun_timer_start (&timer);
        ret = EAGAIN;
      } else if (bind_ret ==  STUN_USAGE_BIND_RETURN_RETRY) {
        ret = EAGAIN;
      } else {
        return bind_ret;
      }
    }
  }
  while (ret == EAGAIN);

  return STUN_USAGE_BIND_RETURN_SUCCESS;
}
