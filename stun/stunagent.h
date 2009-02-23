/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 * (C) 2008 Nokia Corporation. All rights reserved.
 *  Contact: Youness Alaoui
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

#ifndef _STUN_AGENT_H
#define _STUN_AGENT_H

/**
 * SECTION:stunagent
 * @short_description: STUN agent for building and validating STUN messages
 * @see_also: #StunMessage
 * @stability: Stable
 *
 * The STUN Agent allows you to create and validate STUN messages easily.
 * It's main purpose is to make sure the building and validation methods used
 * are compatible with the RFC you create it with. It also tracks the transaction
 * ids of the requests you send, so you can validate if a STUN response you
 * received should be processed by that agent or not.
 *
 */


#ifdef _WIN32
#include "win32_common.h"
#else
#include <stdint.h>
#include <stdbool.h>
#endif


#include <sys/types.h>

typedef struct stun_agent_t StunAgent;

#include "stunmessage.h"

typedef enum {
  STUN_COMPATIBILITY_RFC3489,
  STUN_COMPATIBILITY_RFC5389,
  STUN_COMPATIBILITY_WLM2009,
  STUN_COMPATIBILITY_LAST = STUN_COMPATIBILITY_WLM2009
} StunCompatibility;


typedef enum {
  /* The message is validated */
  STUN_VALIDATION_SUCCESS,
  /* This is not a valid STUN message */
  STUN_VALIDATION_NOT_STUN,
  /* The message seems to be valid but incomplete */
  STUN_VALIDATION_INCOMPLETE_STUN,
  /* The message does not have the cookie or the fingerprint
   * while the agent needs it with its usage */
  STUN_VALIDATION_BAD_REQUEST,
  /* The message is valid but unauthorized with no username and message-integrity
     attributes. A BAD_REQUEST error must be generated */
  STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST,
  /* The message is valid but unauthorized as the username/password do not match.
     An UNAUTHORIZED error must be generated */
  STUN_VALIDATION_UNAUTHORIZED,
  /* The message is valid but this is a response/error that doesn't match
   * a previously sent request */
  STUN_VALIDATION_UNMATCHED_RESPONSE,
  /* The message is valid but contains one or more unknown comprehension
   * attributes. stun_agent_build_unknown_attributes_error should be called */
  STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE,
  /* The message is valid but contains one or more unknown comprehension
   * attributes. This is a response, or error, or indication message
   * and no error response should be sent */
  STUN_VALIDATION_UNKNOWN_ATTRIBUTE,
} StunValidationStatus;

/**
 * StunAgentUsageFlags:
 * @STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS: The agent should be using the short
 * term credentials mechanism for authenticating STUN messages
 * @STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS: The agent should be using the long
 * term credentials mechanism for authenticating STUN messages
 * @STUN_AGENT_USAGE_USE_FINGERPRINT: The agent should add the FINGERPRINT
 * attribute to the STUN messages it creates.
 * @STUN_AGENT_USAGE_ADD_SOFTWARE: The agent should add the SOFTWARE attribute
 * to the STUN messages it creates
 * @STUN_AGENT_USAGE_IGNORE_CREDENTIALS: The agent should ignore any credentials
 * in the STUN messages it receives (the MESSAGE-INTEGRITY attribute
 * will never be validated by stun_agent_validate())
 * @STUN_AGENT_USAGE_NO_INDICATION_AUTH: The agent should ignore credentials
 * in the STUN messages it receives if the #StunClass of the message is
 * #STUN_INDICATION (some implementation require #STUN_INDICATION messages to
 * be authenticated, while others never add a MESSAGE-INTEGRITY attribute to a
 * #STUN_INDICATION message)
 * @STUN_AGENT_USAGE_FORCE_VALIDATER: The agent should always try to validate
 * the password of a STUN message, even if it already knows what the password
 * should be (a response to a previously created request). This means that the
 * #StunMessageIntegrityValidate callback will always be called when there is
 * a MESSAGE-INTEGRITY attribute.
 *
 * This enum defines a bitflag usages for a #StunAgent and they will define how
 * the agent should behave, independently of the compatibility mode it uses.
 * <para> See also: stun_agent_init() </para>
 * <para> See also: stun_agent_validate() </para>
 */
typedef enum {
  STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS    = (1 << 0),
  STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS     = (1 << 1),
  STUN_AGENT_USAGE_USE_FINGERPRINT           = (1 << 2),
  STUN_AGENT_USAGE_ADD_SOFTWARE              = (1 << 3),
  STUN_AGENT_USAGE_IGNORE_CREDENTIALS        = (1 << 4),
  STUN_AGENT_USAGE_NO_INDICATION_AUTH        = (1 << 5),
  STUN_AGENT_USAGE_FORCE_VALIDATER           = (1 << 6),
} StunAgentUsageFlags;


typedef struct {
  StunTransactionId id;
  StunMethod method;
  uint8_t *key;
  size_t key_len;
  uint8_t long_term_key[16];
  bool long_term_valid;
  bool valid;
} StunAgentSavedIds;

struct stun_agent_t {
  StunCompatibility compatibility;
  StunAgentSavedIds sent_ids[STUN_AGENT_MAX_SAVED_IDS];
  uint16_t *known_attributes;
  StunAgentUsageFlags usage_flags;
};

typedef struct {
  uint8_t *username;
  size_t username_len;
  uint8_t *password;
  size_t password_len;
} stun_validater_data;


typedef bool (*StunMessageIntegrityValidate) (StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data);

bool stun_agent_default_validater (StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data);

void stun_agent_init (StunAgent *agent, const uint16_t *known_attributes,
    StunCompatibility compatibility, uint32_t usage_flags);
StunValidationStatus stun_agent_validate (StunAgent *agent, StunMessage *msg,
    const uint8_t *buffer, size_t buffer_len,
    StunMessageIntegrityValidate validater, void * validater_data);
bool stun_agent_init_request (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, StunMethod m);
bool stun_agent_init_indication (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, StunMethod m);
bool stun_agent_init_response (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, const StunMessage *request);
bool stun_agent_init_error (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, const StunMessage *request,
    StunError err);
size_t stun_agent_build_unknown_attributes_error (StunAgent *agent,
    StunMessage *msg, uint8_t *buffer, size_t buffer_len,
    const StunMessage *request);
size_t stun_agent_finish_message (StunAgent *agent, StunMessage *msg,
   const uint8_t *key, size_t key_len);

#endif /* _STUN_AGENT_H */
