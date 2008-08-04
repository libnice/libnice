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
#include "stunagent.h"
#include <errno.h>
#include <arpa/inet.h>

/** ICE connectivity checks **/
#include "ice.h"


size_t
stun_usage_ice_conncheck_create (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len,
    const uint8_t *username, const size_t username_len,
    const uint8_t *password, const size_t password_len,
    bool cand_use, bool controlling, uint32_t priority,
    uint64_t tie, StunUsageIceCompatibility compatibility)
{
  int val;

  stun_agent_init_request (agent, msg, buffer, buffer_len, STUN_BINDING);

  if (compatibility == STUN_USAGE_ICE_COMPATIBILITY_ID19) {
    if (cand_use)
    {
      val = stun_message_append_flag (msg, STUN_ATTRIBUTE_USE_CANDIDATE);
      if (val)
        return 0;
    }

    val = stun_message_append32 (msg, STUN_ATTRIBUTE_PRIORITY, priority);
    if (val)
      return 0;

    if (controlling)
      val = stun_message_append64 (msg, STUN_ATTRIBUTE_ICE_CONTROLLING, tie);
    else
      val = stun_message_append64 (msg, STUN_ATTRIBUTE_ICE_CONTROLLED, tie);
    if (val)
      return 0;
  }

  if (username && username_len > 0) {
    val = stun_message_append_bytes (msg, STUN_ATTRIBUTE_USERNAME,
        username, username_len);
    if (val)
      return 0;
  }

  return stun_agent_finish_message (agent, msg, password, password_len);

}


StunUsageIceReturn stun_usage_ice_conncheck_process (StunMessage *msg,
    struct sockaddr *addr, socklen_t *addrlen,
    struct sockaddr *alternate_server, socklen_t *alternate_server_len,
    StunUsageIceCompatibility compatibility)
{
  int val, code = -1;

  switch (stun_message_get_class (msg))
  {
    case STUN_REQUEST:
    case STUN_INDICATION:
      return STUN_USAGE_ICE_RETURN_RETRY;

    case STUN_RESPONSE:
      break;

    case STUN_ERROR:
      if (stun_message_find_error (msg, &code) != 0) {
        /* missing ERROR-CODE: ignore message */
        return STUN_USAGE_ICE_RETURN_RETRY;
      }

      if (code  == STUN_ERROR_ROLE_CONFLICT)
        return STUN_USAGE_ICE_RETURN_ROLE_CONFLICT;

      /* NOTE: currently we ignore unauthenticated messages if the context
       * is authenticated, for security reasons. */
      stun_debug (" STUN error message received (code: %d)\n", code);

      /* ALTERNATE-SERVER mechanism */
      if ((code / 100) == 3) {
        if (alternate_server && alternate_server_len) {
          if (stun_message_find_addr (msg, STUN_ATTRIBUTE_ALTERNATE_SERVER,
                  alternate_server, alternate_server_len)) {
            stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute\n");
            return STUN_USAGE_ICE_RETURN_ERROR;
          }
        } else {
          if (!stun_message_has_attribute (msg, STUN_ATTRIBUTE_ALTERNATE_SERVER)) {
            stun_debug (" Unexpectedly missing ALTERNATE-SERVER attribute\n");
            return STUN_USAGE_ICE_RETURN_ERROR;
          }
        }

        stun_debug ("Found alternate server\n");
        return STUN_USAGE_ICE_RETURN_ALTERNATE_SERVER;

      }
      return STUN_USAGE_ICE_RETURN_ERROR;
  }

  stun_debug ("Received %u-bytes STUN message\n", stun_message_length (msg));

  if (compatibility == STUN_USAGE_ICE_COMPATIBILITY_MSN) {
    stun_transid_t transid;
    uint32_t magic_cookie;
    stun_message_id (msg, transid);
    magic_cookie = *((uint32_t *) transid);

    val = stun_message_find_xor_addr_full (msg,
        STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, addr, addrlen, htonl (magic_cookie));
  } else {
    val = stun_message_find_xor_addr (msg,
        STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, addr, addrlen);
  }
  if (val)
  {
    stun_debug (" No XOR-MAPPED-ADDRESS: %s\n", strerror (val));
    val = stun_message_find_addr (msg,
        STUN_ATTRIBUTE_MAPPED_ADDRESS, addr, addrlen);
    if (val)
    {
      stun_debug (" No MAPPED-ADDRESS: %s\n", strerror (val));
      return STUN_USAGE_ICE_RETURN_ERROR;
    }
  }

  stun_debug ("Mapped address found!\n");
  return STUN_USAGE_ICE_RETURN_SUCCESS;
}

static int
stun_bind_error (StunAgent *agent, StunMessage *msg,
    uint8_t *buf, size_t *plen, const StunMessage *req,
    stun_error_t code)
{
  size_t len = *plen;
  int val;

  *plen = 0;
  stun_debug ("STUN Error Reply (buffer size: %u)...\n", (unsigned)len);

  val = stun_agent_init_error (agent, msg, buf, len, req, code);
  if (!val)
    return val;

  len = stun_agent_finish_message (agent, msg, NULL, 0);
  if (len == 0)
    return 0;

  *plen = len;
  stun_debug (" Error response (%u) of %u bytes\n", (unsigned)code,
       (unsigned)*plen);
  return 1;
}

int
stun_usage_ice_conncheck_create_reply (StunAgent *agent, StunMessage *req,
    StunMessage *msg, uint8_t *buf, size_t *plen,
    const struct sockaddr *src, socklen_t srclen,
    bool *restrict control, uint64_t tie,
    StunUsageIceCompatibility compatibility)
{
  const char *username = NULL;
  uint16_t username_len;
  size_t len = *plen;
  uint64_t q;
  int val = 0, ret = 0;


#define err( code ) \
  stun_bind_error (agent, msg, buf, &len, req, code); \
  *plen = len

  *plen = 0;
  stun_debug ("STUN Reply (buffer size = %u)...\n", (unsigned)len);

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

  if (stun_agent_init_response (agent, msg, buf, len, req) == FALSE) {
    stun_debug ("Unable to create response\n");
    goto failure;
  }
  if (compatibility == STUN_USAGE_ICE_COMPATIBILITY_MSN) {
    stun_transid_t transid;
    uint32_t magic_cookie;
    stun_message_id (msg, transid);
    magic_cookie = *((uint32_t *) transid);

    val = stun_message_append_xor_addr_full (msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
        src, srclen, htonl (magic_cookie));
  } else if (stun_has_cookie (msg)) {
    val = stun_message_append_xor_addr (msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
        src, srclen);
  } else {
    val = stun_message_append_addr (msg, STUN_ATTRIBUTE_MAPPED_ADDRESS,
        src, srclen);
  }

  if (val) {
    stun_debug (" Mapped address problem: %s\n", strerror (val));
    goto failure;
  }

  username = (const char *)stun_message_find (req,
      STUN_ATTRIBUTE_USERNAME, &username_len);
  if (username) {
    stun_message_append_bytes (msg, STUN_ATTRIBUTE_USERNAME,
        username, username_len);
  }

  /* the stun agent will automatically use the password of the request */
  len = stun_agent_finish_message (agent, msg, NULL, 0);
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


uint32_t stun_usage_ice_conncheck_priority (const StunMessage *msg)
{
  uint32_t value;

  if (stun_message_find32 (msg, STUN_ATTRIBUTE_PRIORITY, &value))
    return 0;
  return value;
}


bool stun_usage_ice_conncheck_use_candidate (const StunMessage *msg)
{
  return !stun_message_find_flag (msg, STUN_ATTRIBUTE_USE_CANDIDATE);
}



#if 0

/** STUN NAT control */
struct stun_nested_s
{
  stun_bind_t *bind;
  struct sockaddr_storage mapped;
  uint32_t refresh;
  uint32_t bootnonce;
};


int stun_nested_start (stun_nested_t **restrict context, int fd,
                       const struct sockaddr *restrict mapad,
                       const struct sockaddr *restrict natad,
                       socklen_t adlen, uint32_t refresh, int compat)
{
  stun_nested_t *ctx;
  int val;

  if (adlen > sizeof (ctx->mapped))
    return ENOBUFS;

  ctx = malloc (sizeof (*ctx));
  memcpy (&ctx->mapped, mapad, adlen);
  ctx->refresh = 0;
  ctx->bootnonce = 0;

  /* TODO: forcily set port to 3478 */
  val = stun_bind_alloc (&ctx->bind, fd, natad, adlen, compat);
  if (val)
    return val;

  *context = ctx;

  val = stun_message_append32 (&ctx->bind->trans.message,
                       STUN_ATTRIBUTE_REFRESH_INTERVAL, refresh);
  if (val)
    goto error;

  val = stun_agent_finish_message (&ctx->bind->agent,
      &ctx->bind->trans.message, NULL, 0);
  if (val)
    goto error;

  val = stun_trans_start (&ctx->bind->trans);
  if (val)
    goto error;

  return 0;

error:
  stun_bind_cancel (ctx->bind);
  return val;
}


int stun_nested_process (stun_nested_t *restrict ctx,
                         const void *restrict buf, size_t len,
                         struct sockaddr *restrict intad, socklen_t *adlen)
{
  struct sockaddr_storage mapped;
  socklen_t mappedlen = sizeof (mapped);
  int val;

  assert (ctx != NULL);

  val = stun_bind_process (ctx->bind, buf, len,
                           (struct sockaddr *)&mapped, &mappedlen);
  if (val)
    return val;

  /* Mapped address mistmatch! (FIXME: what are we really supposed to do
   * in this case???) */
  if (sockaddrcmp ((struct sockaddr *)&mapped,
                   (struct sockaddr *)&ctx->mapped))
  {
    stun_debug (" Mapped address mismatch! (Symmetric NAT?)\n");
    return ECONNREFUSED;
  }

  val = stun_message_find_xor_addr (&ctx->bind->trans.message,
      STUN_ATTRIBUTE_XOR_INTERNAL_ADDRESS,
      intad, adlen);
  if (val)
  {
    stun_debug (" No XOR-INTERNAL-ADDRESS: %s\n", strerror (val));
    return val;
  }

  stun_message_find32 (&ctx->bind->trans.message,
      STUN_ATTRIBUTE_REFRESH_INTERVAL, &ctx->refresh);
  /* TODO: give this to caller */

  stun_debug (" Internal address found!\n");
  stun_bind_cancel (ctx->bind);
  ctx->bind = NULL;
  return 0;
}
#endif
