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

#ifndef STUN_CONNCHECK_H
# define STUN_CONNCHECK_H 1

/**
 * @file stun-ice.h
 * @brief STUN/ICE connectivity checks
 */

# include "stun/tools/bind.h"
# include "stun/stunagent.h"

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Starts a connectivity check using STUN Binding discovery.
 *
 * @param context pointer to an opaque pointer that will be passed to
 * stun_bind_resume() afterward
 * @param fd socket to use for discovery, or -1 to create one
 * @param srv STUN server socket address
 * @param srvlen STUN server socket address length
 * @param username nul-terminated username for authentication
 * (need not be kept valid after return)
 * @param password nul-terminated shared secret (ICE password)
 * (need not be kept valid after return)
 * @param cand_use whether to include a USE-CANDIDATE flag
 * @param priority host-byte order PRIORITY value
 * @param controlling whether we are in controlling (true) or
 * controlled (false) state
 * @param tie control tie breaker value (host-byte order)
 *
 * @return 0 on success, a standard error value otherwise.
 */
int stun_conncheck_start (stun_bind_t **restrict context, int fd,
    const struct sockaddr *restrict srv, socklen_t srvlen,
    const char *username, const char *password,
    bool cand_use, bool controlling, uint32_t priority,
    uint64_t tie, uint32_t compat);

/**
 * Tries to parse a STUN connectivity check (Binding request) and format a
 * response accordingly.
 *
 * @param buf [OUT] output buffer to write a Binding response to. May refer
 * to the same buffer space as the request message.
 * @param plen [IN/OUT] output buffer size on entry, response length on exit
 * @param msg pointer to the first byte of the binding request
 * @param src socket address the message was received from
 * @param srclen byte length of the socket address
 * @param username STUN username
 * @param password HMAC secret password
 * @param control [IN/OUT] whether we are controlling ICE or not
 * @param tie tie breaker value for ICE role determination
 *
 * @return 0 if successful (@a rbuf contains a <b>non-error</b> response),
 * EINVAL: malformatted request message or socket address,
 * EAFNOSUPPORT: unsupported socket address family,
 * EPROTO: unsupported request message type or parameter,
 * ENOBUFS: insufficient response buffer space.
 * EACCES: ICE role conflict occurred, please recheck the flag at @a control
 *
 * In case of error, the value at @a plen is set to the size of an error
 * response, or 0 if no error response should be sent.
 */
int
stun_conncheck_reply (StunAgent *agent, StunMessage *req,
    const uint8_t *rbuf, size_t rlen,
    StunMessage *msg, uint8_t *buf, size_t *plen,
    const struct sockaddr *restrict src, socklen_t srclen,
    const uint8_t *local_ufrag, const size_t ufrag_len,
    const uint8_t *password, const size_t password_len,
    bool *restrict control, uint64_t tie, uint32_t compat);

/**
 * Extracts the priority from a STUN message.
 * @param msg valid STUN message.
 * @return host byte order priority, or 0 if not specified.
 */
uint32_t stun_conncheck_priority (const StunMessage *msg);

/**
 * Extracts the "use candidate" flag from a STUN message.
 * @param msg valid STUN message.
 * @return true if the flag is set, false if not.
 */
bool stun_conncheck_use_candidate (const StunMessage *msg);

# ifdef __cplusplus
}
# endif

#endif
