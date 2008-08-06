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

#ifndef STUN_TURN_H
# define STUN_TURN_H 1

/**
 * @file bind.h
 * @brief STUN binding discovery
 */

# include <stdbool.h>
# include <stdint.h>

# include "stun/stunagent.h"

# ifdef __cplusplus
extern "C" {
# endif


#define STUN_USAGE_TURN_REQUEST_PORT_NORMAL       0
#define STUN_USAGE_TURN_REQUEST_PORT_ODD          1
#define STUN_USAGE_TURN_REQUEST_PORT_EVEN         2
#define STUN_USAGE_TURN_REQUEST_PORT_BOTH         3
#define STUN_USAGE_TURN_REQUEST_PORT_PRESERVING   8

typedef enum {
  STUN_USAGE_TURN_COMPATIBILITY_TD9,
  STUN_USAGE_TURN_COMPATIBILITY_GOOGLE,
  STUN_USAGE_TURN_COMPATIBILITY_MSN,
} StunUsageTurnCompatibility;

typedef enum {
  STUN_USAGE_TURN_RETURN_SUCCESS,
  STUN_USAGE_TURN_RETURN_ERROR,
  STUN_USAGE_TURN_RETURN_RETRY,
  STUN_USAGE_TURN_RETURN_ALTERNATE_SERVER,
} StunUsageTurnReturn;


size_t stun_usage_turn_create (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len,
    StunMessage *previous_request,
    uint32_t request_ports,
    uint32_t bandwidth, uint32_t lifetime,
    uint8_t *username, size_t username_len,
    uint8_t *password, size_t password_len,
    StunUsageTurnCompatibility compatibility);

size_t stun_usage_turn_create_refresh (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len,
    StunMessage *previous_request, int lifetime,
    StunUsageTurnCompatibility compatibility);

StunUsageTurnReturn stun_usage_turn_process (StunMessage *msg,
    struct sockaddr *relay_addr, socklen_t *relay_addrlen,
    struct sockaddr *addr, socklen_t *addrlen,
    struct sockaddr *alternate_server, socklen_t *alternate_server_len,
    uint32_t *bandwidth, uint32_t *lifetime,
    StunUsageTurnCompatibility compatibility);

# ifdef __cplusplus
}
# endif

#endif
