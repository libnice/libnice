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


#ifdef _WIN32
#include "win32_common.h"
#else
# include <stdbool.h>
# include <stdint.h>
#endif

# include "stun/stunagent.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef enum {
  STUN_USAGE_BIND_RETURN_SUCCESS,
  STUN_USAGE_BIND_RETURN_ERROR,
  STUN_USAGE_BIND_RETURN_RETRY,
  STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER,
  STUN_USAGE_BIND_RETURN_TIMEOUT,
} StunUsageBindReturn;


size_t stun_usage_bind_create (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len);

StunUsageBindReturn stun_usage_bind_process (StunMessage *msg,
    struct sockaddr *addr, socklen_t *addrlen,
    struct sockaddr *alternate_server, socklen_t *alternate_server_len);

size_t stun_usage_bind_keepalive (StunAgent *agent, StunMessage *msg,
    uint8_t *buf, size_t len);


StunUsageBindReturn stun_usage_bind_run (const struct sockaddr *srv,
    socklen_t srvlen, struct sockaddr *addr, socklen_t *addrlen);

# ifdef __cplusplus
}
# endif

#endif
