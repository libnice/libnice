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

#include <sys/types.h>
#include <sys/socket.h>

#include "stun/stunagent.h"
#include "turn.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>


/** Non-blocking mode STUN TURN usage */

size_t stun_usage_turn_create (StunAgent *agent, StunMessage *msg,
    uint8_t *username, size_t username_len,
    uint8_t *password, size_t password_len,
    uint8_t *buffer, size_t buffer_len)
{
  stun_agent_init_request (agent, msg, buffer, buffer_len, STUN_ALLOCATE);

  if (username != NULL && username_len > 0) {
    if (stun_message_append_bytes (msg, STUN_ATTRIBUTE_USERNAME,
            username, username_len) != 0)
      return 0;
  }

  return stun_agent_finish_message (agent, msg, password, password_len);
}

StunUsageTurnReturn stun_usage_turn_process (StunMessage *msg,
    struct sockaddr *addr, socklen_t *addrlen,
    struct sockaddr *alternate_server, socklen_t *alternate_server_len,
    uint32_t *bandwidth, uint32_t *lifetime)
{
  int val, code = -1;

  switch (stun_message_get_class (msg))
  {
    case STUN_REQUEST:
    case STUN_INDICATION:
      return STUN_USAGE_TURN_RETURN_RETRY;

    case STUN_RESPONSE:
      break;

    case STUN_ERROR:
      if (stun_message_find_error (msg, &code) != 0) {
        /* missing ERROR-CODE: ignore message */
        return STUN_USAGE_TURN_RETURN_RETRY;
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
            return STUN_USAGE_TURN_RETURN_ERROR;
          }
        } else {
          if (!stun_message_has_attribute (msg, STUN_ATTRIBUTE_ALTERNATE_SERVER)) {
            stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute\n");
            return STUN_USAGE_TURN_RETURN_ERROR;
          }
        }

        stun_debug ("Found alternate server\n");
        return STUN_USAGE_TURN_RETURN_ALTERNATE_SERVER;

      }
      return STUN_USAGE_TURN_RETURN_ERROR;
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
      return STUN_USAGE_TURN_RETURN_ERROR;
    }
  }

  stun_debug (" Mapped address found!\n");
  return STUN_USAGE_TURN_RETURN_SUCCESS;

}
