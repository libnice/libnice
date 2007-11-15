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
#include "bind.h"
#include "stun-msg.h"
#include <errno.h>

/** ICE connectivity checks **/
#include "stun-ice.h"


static int
stun_bind_error (uint8_t *buf, size_t *plen, const uint8_t *req,
                 stun_error_t code, const char *pass)
{
  size_t len = *plen;
  int val;

  *plen = 0;
  DBG ("STUN Error Reply (buffer size: %u)...\n", (unsigned)len);

  val = stun_init_error (buf, len, req, code);
  if (val)
    return val;

  val = stun_finish_short (buf, &len, NULL, pass, NULL);
  if (val)
    return val;

  *plen = len;
  DBG (" Error response (%u) of %u bytes\n", (unsigned)code,
       (unsigned)*plen);
  return 0;
}


int
stun_conncheck_reply (uint8_t *restrict buf, size_t *restrict plen,
                      const uint8_t *msg,
                      const struct sockaddr *restrict src, socklen_t srclen,
                      const char *username, const char *pass,
                      bool *restrict control, uint64_t tie)
{
  size_t len = *plen;
  uint64_t q;
  int val, ret = 0;

#define err( code ) \
  stun_bind_error (buf, &len, msg, code, pass); \
  *plen = len

  *plen = 0;
  DBG ("STUN Reply (buffer size = %u)...\n", (unsigned)len);

  if (stun_get_class (msg) != STUN_REQUEST)
  {
    DBG (" Unhandled non-request (class %u) message.\n",
         stun_get_class (msg));
    return EINVAL;
  }

  if (!stun_demux (msg))
  {
    DBG (" Incorrectly multiplexed STUN message ignored.\n");
    return EINVAL;
  }

  if (stun_has_unknown (msg))
  {
    DBG (" Unknown mandatory attributes in message.\n");
    val = stun_init_error_unknown (buf, len, msg);
    if (!val)
      val = stun_finish_short (buf, &len, NULL, pass, NULL);
    if (val)
      goto failure;

    *plen = len;
    return EPROTO;
  }

  /* Short term credentials checking */
  val = 0;
  if (!stun_present (msg, STUN_MESSAGE_INTEGRITY)
   || !stun_present (msg, STUN_USERNAME))
  {
    DBG (" Missing USERNAME or MESSAGE-INTEGRITY.\n");
    val = STUN_BAD_REQUEST;
  }
  else
  if (stun_strcmp (msg, STUN_USERNAME, username)
   || stun_verify_password (msg, pass))
  {
    DBG (" Integrity check failed.\n");
    val = STUN_UNAUTHORIZED;
  }

  if (val)
  {
    stun_bind_error (buf, &len, msg, val, NULL);
    *plen = len;
    return EPERM;
  }

  if (stun_get_method (msg) != STUN_BINDING)
  {
    DBG (" Bad request (method %u) message.\n",
         stun_get_method (msg));
    err (STUN_BAD_REQUEST);
    return EPROTO;
  }

  /* Role conflict handling */
  assert (control != NULL);
  if (!stun_find64 (msg, *control ? STUN_ICE_CONTROLLING
                                  : STUN_ICE_CONTROLLED, &q))
  {
    DBG ("STUN Role Conflict detected:\n");

    if (tie < q)
    {
      DBG (" switching role from \"controll%s\" to \"controll%s\"\n",
           *control ? "ing" : "ed", *control ? "ed" : "ing");
      *control = !*control;
      ret = EACCES;
    }
    else
    {
      DBG (" staying \"controll%s\" (sending error)\n",
           *control ? "ing" : "ed");
      *plen = len;
      err (STUN_ROLE_CONFLICT);
      return 0;
    }
  }
#ifndef NDEBUG
  else
  if (stun_find64 (msg, *control ? STUN_ICE_CONTROLLED
                                 : STUN_ICE_CONTROLLING, &q))
    DBG ("STUN Role not specified by peer!\n");
#endif

  stun_init_response (buf, len, msg);
  val = stun_append_xor_addr (buf, len, STUN_XOR_MAPPED_ADDRESS,
                              src, srclen);
  if (val)
  {
    DBG (" Mapped address problem: %s\n", strerror (val));
    goto failure;
  }

  val = stun_finish_short (buf, &len, NULL, pass, NULL);
  if (val)
    goto failure;

  *plen = len;
  DBG (" All done (response size: %u)\n", (unsigned)len);
  return ret;

failure:
  assert (*plen == 0);
  DBG (" Fatal error formatting Response: %s\n", strerror (val));
  return val;
}
#undef err


uint32_t stun_conncheck_priority (const uint8_t *msg)
{
  uint32_t value;

  if (stun_find32 (msg, STUN_PRIORITY, &value))
    return 0;
  return value;
}


bool stun_conncheck_use_candidate (const uint8_t *msg)
{
  return !stun_find_flag (msg, STUN_USE_CANDIDATE);
}
