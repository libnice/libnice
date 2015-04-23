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
#include "stun/stunagent.h"
#include "stun/usages/ice.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define MSG_DONTWAIT 0
#define MSG_NOSIGNAL 0

#define alarm(...)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#undef NDEBUG /* ensure assertions are built-in */
#include <assert.h>


int main (void)
{
  union {
    struct sockaddr sa;
    struct sockaddr_storage storage;
    struct sockaddr_in ip4;
  } addr;
  uint8_t req_buf[STUN_MAX_MESSAGE_SIZE];
  uint8_t resp_buf[STUN_MAX_MESSAGE_SIZE];
  const const uint64_t tie = 0x8000000000000000LL;
  StunMessageReturn val;
  StunUsageIceReturn val2;
  size_t len;
  size_t rlen;
  static char username[] = "L:R";
  static uint8_t ufrag[] = "L", pass[] = "secret";
  size_t ufrag_len = strlen ((char*) ufrag);
  size_t pass_len = strlen ((char*) pass);
  int code;
  bool control = false;
  StunAgent agent;
  StunMessage req;
  StunMessage resp;
  StunDefaultValidaterData validater_data[] = {
    {ufrag, ufrag_len, pass, pass_len},
    {(uint8_t *) username, strlen (username), pass, pass_len},
    {NULL, 0, NULL, 0}};
  StunValidationStatus valid;

  stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_USE_FINGERPRINT |
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS);

  memset (&addr, 0, sizeof (addr));
  addr.ip4.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
  addr.ip4.sin_len = sizeof (addr);
#endif
  addr.ip4.sin_port = htons (12345);
  addr.ip4.sin_addr.s_addr = htonl (0x7f000001);

  /* Incorrect message class */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  assert (stun_agent_init_response (&agent, &req, req_buf, sizeof (req_buf), &req));

  rlen = stun_agent_finish_message (&agent, &req, NULL, 0);
  assert (rlen > 0);

  len = sizeof (resp_buf);
  val2 = stun_usage_ice_conncheck_create_reply (&agent, &req,
      &resp, resp_buf, &len, &addr.storage,
      sizeof (addr.ip4), &control, tie, STUN_USAGE_ICE_COMPATIBILITY_RFC5245);
  assert (val2 == STUN_USAGE_ICE_RETURN_INVALID_REQUEST);
  assert (len == 0);

  /* Incorrect message method */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), 0x666));
  val = stun_message_append_string (&req, STUN_ATTRIBUTE_USERNAME, username);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  rlen = stun_agent_finish_message (&agent, &req, pass, pass_len);
  assert (rlen > 0);

  len = sizeof (resp_buf);
  val2 = stun_usage_ice_conncheck_create_reply (&agent, &req,
      &resp, resp_buf, &len, &addr.storage,
      sizeof (addr.ip4), &control, tie, STUN_USAGE_ICE_COMPATIBILITY_RFC5245);
  assert (val2 == STUN_USAGE_ICE_RETURN_INVALID_METHOD);
  assert (len > 0);

  /* Unknown attribute */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  val = stun_message_append_string (&req, 0x666, "The evil unknown attribute!");
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  val = stun_message_append_string (&req, STUN_ATTRIBUTE_USERNAME, username);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  rlen = stun_agent_finish_message (&agent, &req, pass, pass_len);
  assert (rlen > 0);

  valid = stun_agent_validate (&agent, &req, req_buf, rlen,
      stun_agent_default_validater, validater_data);

  assert (valid == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE);

  /* Unauthenticated message */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  rlen = stun_agent_finish_message (&agent, &req, NULL, 0);
  assert (rlen > 0);

  valid = stun_agent_validate (&agent, &req, req_buf, rlen,
      stun_agent_default_validater, validater_data);

  assert (valid == STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST);

  /* No username */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  rlen = stun_agent_finish_message (&agent, &req, pass, pass_len);
  assert (rlen > 0);

  valid = stun_agent_validate (&agent, &req, req_buf, rlen,
      stun_agent_default_validater, validater_data);

  assert (valid == STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST);
  assert (stun_usage_ice_conncheck_priority (&req) == 0);
  assert (stun_usage_ice_conncheck_use_candidate (&req) == false);

  /* Good message */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  val = stun_message_append32 (&req, STUN_ATTRIBUTE_PRIORITY, 0x12345678);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  val = stun_message_append_flag (&req, STUN_ATTRIBUTE_USE_CANDIDATE);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  val = stun_message_append_string (&req, STUN_ATTRIBUTE_USERNAME,
      (char*) ufrag);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  rlen = stun_agent_finish_message (&agent, &req, pass, pass_len);
  assert (rlen > 0);

  len = sizeof (resp_buf);
  val2 = stun_usage_ice_conncheck_create_reply (&agent, &req,
      &resp, resp_buf, &len, &addr.storage,
      sizeof (addr.ip4), &control, tie, STUN_USAGE_ICE_COMPATIBILITY_RFC5245);
  assert (val2 == STUN_USAGE_ICE_RETURN_SUCCESS);
  assert (len > 0);
  assert (stun_agent_validate (&agent, &resp, resp_buf, len,
          stun_agent_default_validater, validater_data) == STUN_VALIDATION_SUCCESS);
  assert (stun_message_get_class (&resp) == STUN_RESPONSE);
  assert (stun_usage_ice_conncheck_priority (&req) == 0x12345678);
  assert (stun_usage_ice_conncheck_use_candidate (&req) == true);

  /* Invalid socket address */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  val = stun_message_append_string (&req, STUN_ATTRIBUTE_USERNAME,
      (char *) ufrag);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  rlen = stun_agent_finish_message (&agent, &req, pass, pass_len);
  assert (rlen > 0);

  addr.ip4.sin_family = AF_UNSPEC;
  len = sizeof (resp_buf);
  val2 = stun_usage_ice_conncheck_create_reply (&agent, &req,
      &resp, resp_buf, &len, &addr.storage,
      sizeof (addr.ip4), &control, tie, STUN_USAGE_ICE_COMPATIBILITY_RFC5245);
  assert (val2 == STUN_USAGE_ICE_RETURN_INVALID_ADDRESS);
  assert (len == 0);

  addr.ip4.sin_family = AF_INET;

  /* Lost role conflict */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  val = stun_message_append64 (&req, STUN_ATTRIBUTE_ICE_CONTROLLING, tie + 1);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  val = stun_message_append_string (&req, STUN_ATTRIBUTE_USERNAME,
     (char *) ufrag);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  rlen = stun_agent_finish_message (&agent, &req, pass, pass_len);
  assert (rlen > 0);


  len = sizeof (resp_buf);
  control = true;
  val2 = stun_usage_ice_conncheck_create_reply (&agent, &req,
      &resp, resp_buf, &len, &addr.storage,
      sizeof (addr.ip4), &control, tie, STUN_USAGE_ICE_COMPATIBILITY_RFC5245);
  assert (val2 == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT);
  assert (len > 0);
  assert (control == false);
  assert (stun_agent_validate (&agent, &resp, resp_buf, len,
          stun_agent_default_validater, validater_data) == STUN_VALIDATION_SUCCESS);
  assert (stun_message_get_class (&resp) == STUN_RESPONSE);

  /* Won role conflict */
  assert (stun_agent_init_request (&agent, &req, req_buf, sizeof(req_buf), STUN_BINDING));
  val = stun_message_append64 (&req, STUN_ATTRIBUTE_ICE_CONTROLLED, tie - 1);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  val = stun_message_append_string (&req, STUN_ATTRIBUTE_USERNAME,
      (char *) ufrag);
  assert (val == STUN_MESSAGE_RETURN_SUCCESS);
  rlen = stun_agent_finish_message (&agent, &req, pass, pass_len);
  assert (rlen > 0);

  len = sizeof (resp_buf);
  control = false;
  val2 = stun_usage_ice_conncheck_create_reply (&agent, &req,
      &resp, resp_buf, &len, &addr.storage,
      sizeof (addr.ip4), &control, tie, STUN_USAGE_ICE_COMPATIBILITY_RFC5245);
  assert (val2 == STUN_USAGE_ICE_RETURN_SUCCESS);
  assert (len > 0);
  assert (control == false);
  assert (stun_agent_validate (&agent, &resp, resp_buf, len,
          stun_agent_default_validater, validater_data) == STUN_VALIDATION_SUCCESS);
  assert (stun_message_get_class (&resp) == STUN_ERROR);
  stun_message_find_error (&resp, &code);
  assert (code == STUN_ERROR_ROLE_CONFLICT);


  return 0;
}
