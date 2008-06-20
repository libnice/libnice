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

#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include "stun/usages/bind.h"
#include "stunagent.h"
#include <errno.h>

/** ICE connectivity checks **/
#include "stun-ice.h"


static int
stun_bind_error (StunAgent *agent, StunMessage *msg,
    uint8_t *buf, size_t *plen, const StunMessage *req,
    stun_error_t code, const uint8_t *key, size_t key_len)
{
  size_t len = *plen;
  int val;

  *plen = 0;
  stun_debug ("STUN Error Reply (buffer size: %u)...\n", (unsigned)len);

  val = stun_agent_init_error (agent, msg, buf, len, req, code);
  if (!val)
    return val;

  len = stun_agent_finish_message (agent, msg, key, key_len);
  if (len == 0)
    return 0;

  *plen = len;
  stun_debug (" Error response (%u) of %u bytes\n", (unsigned)code,
       (unsigned)*plen);
  return 1;
}


int
stun_conncheck_reply (StunAgent *agent, StunMessage *req,
    const uint8_t *rbuf, size_t rlen,
    StunMessage *msg, uint8_t *buf, size_t *plen,
    const struct sockaddr *restrict src, socklen_t srclen,
    const uint8_t *local_ufrag, const size_t ufrag_len,
    const uint8_t *password, const size_t password_len,
    bool *restrict control, uint64_t tie, uint32_t compat)
{
  const char *username = NULL;
  uint16_t username_len;
  size_t len = *plen;
  uint64_t q;
  int val = 0, ret = 0;
  stun_validater_data validater_data[] = {
    {local_ufrag, ufrag_len, password, password_len},
    {NULL, 0, NULL, 0}};
  StunValidationStatus valid;


#define err( code ) \
  stun_bind_error (agent, msg, buf, &len, req, code, password, password_len); \
  *plen = len

  *plen = 0;
  stun_debug ("STUN Reply (buffer size = %u)...\n", (unsigned)len);

  valid = stun_agent_validate (agent, req, rbuf, rlen,
      stun_agent_default_validater, validater_data);

  stun_debug ("validated : %d\n", valid);

  if (valid == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE)
  {
    stun_debug (" Unknown mandatory attributes in message.\n");
    len = stun_agent_build_unknown_attributes_error (agent, msg, buf, len, req);
    if (len == 0)
      goto failure;

    *plen = len;
    return EPROTO;
  }

  if (valid == STUN_VALIDATION_NOT_STUN ||
      valid == STUN_VALIDATION_INCOMPLETE_STUN ||
      valid == STUN_VALIDATION_BAD_REQUEST)
  {
    stun_debug (" Incorrectly multiplexed STUN message ignored.\n");
    return EINVAL;
  }

  if (stun_message_get_class (req) != STUN_REQUEST)
  {
    stun_debug (" Unhandled non-request (class %u) message.\n",
         stun_message_get_class (req));
    return EINVAL;
  }

  if (stun_message_get_method (req) != STUN_BINDING)
  {
    stun_debug (" Bad request (method %u) message.\n",
         stun_message_get_method (req));
    err (STUN_ERROR_BAD_REQUEST);
    return EPROTO;
  }

  if (valid == STUN_VALIDATION_UNAUTHORIZED) {
    stun_debug (" Integrity check failed.\n");
    err (STUN_ERROR_UNAUTHORIZED);
    return EPERM;
  }
  if (valid == STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST) {
    stun_debug (" Integrity check failed.\n");
    err (STUN_ERROR_BAD_REQUEST);
    return EPERM;
  }

  username = (const char *)stun_message_find (req,
      STUN_ATTRIBUTE_USERNAME, &username_len);

  /* Role conflict handling */
  assert (control != NULL);
  if (!stun_message_find64 (req, *control ? STUN_ATTRIBUTE_ICE_CONTROLLING
                                          : STUN_ATTRIBUTE_ICE_CONTROLLED, &q))
  {
    stun_debug ("STUN Role Conflict detected:\n");

    if (tie < q)
    {
      stun_debug (" switching role from \"controll%s\" to \"controll%s\"\n",
           *control ? "ing" : "ed", *control ? "ed" : "ing");
      *control = !*control;
      ret = EACCES;
    }
    else
    {
      stun_debug (" staying \"controll%s\" (sending error)\n",
           *control ? "ing" : "ed");
      *plen = len;
      err (STUN_ERROR_ROLE_CONFLICT);
      return 0;
    }
  }
#ifndef NDEBUG
  else
  if (stun_message_find64 (req, *control ? STUN_ATTRIBUTE_ICE_CONTROLLED
                                         : STUN_ATTRIBUTE_ICE_CONTROLLING, &q))
    stun_debug ("STUN Role not specified by peer!\n");
#endif

  stun_agent_init_response (agent, msg, buf, len, req);
  if (!stun_has_cookie (msg)) {
    val = stun_message_append_addr (msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, src, srclen);
  } else {
    val = stun_message_append_xor_addr (msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
        src, srclen);
  }

  if (val)
  {
    stun_debug (" Mapped address problem: %s\n", strerror (val));
    goto failure;
  }

  if (username) {
    stun_message_append_bytes (msg, STUN_ATTRIBUTE_USERNAME,
        username, username_len);
  }

  len = stun_agent_finish_message (agent, msg, password, password_len);
  if (len == 0)
    goto failure;

  *plen = len;
  stun_debug (" All done (response size: %u)\n", (unsigned)len);
  return ret;

failure:
  assert (*plen == 0);
  stun_debug (" Fatal error formatting Response: %s\n", strerror (val));
  return val;
}
#undef err


uint32_t stun_conncheck_priority (const StunMessage *msg)
{
  uint32_t value;

  if (stun_message_find32 (msg, STUN_ATTRIBUTE_PRIORITY, &value))
    return 0;
  return value;
}


bool stun_conncheck_use_candidate (const StunMessage *msg)
{
  return !stun_message_find_flag (msg, STUN_ATTRIBUTE_USE_CANDIDATE);
}
