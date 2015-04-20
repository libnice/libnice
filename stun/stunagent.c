/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008-2009 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
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

#include "stunmessage.h"
#include "stunagent.h"
#include "stunhmac.h"
#include "stun5389.h"
#include "utils.h"

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>


static bool stun_agent_is_unknown (StunAgent *agent, uint16_t type);
static unsigned stun_agent_find_unknowns (StunAgent *agent,
    const StunMessage * msg, uint16_t *list, unsigned max);

void stun_agent_init (StunAgent *agent, const uint16_t *known_attributes,
    StunCompatibility compatibility, StunAgentUsageFlags usage_flags)
{
  int i;

  agent->known_attributes = (uint16_t *) known_attributes;
  agent->compatibility = compatibility;
  agent->usage_flags = usage_flags;
  agent->software_attribute = NULL;

  for (i = 0; i < STUN_AGENT_MAX_SAVED_IDS; i++) {
    agent->sent_ids[i].valid = FALSE;
  }
}


bool stun_agent_default_validater (StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data)
{
  StunDefaultValidaterData* val = (StunDefaultValidaterData *) user_data;
  int i;

  for (i = 0; val && val[i].username ; i++) {
#if 0
    stun_debug ("Comparing username of size %d and %" PRIuPTR ": %d",
        username_len, val[i].username_len,
        (memcmp (username, val[i].username, username_len) == 0));
#endif
    stun_debug_bytes ("  First username: ", username, username_len);
    stun_debug_bytes ("  Second username: ", val[i].username,
        val[i].username_len);
    if (username_len == val[i].username_len &&
        memcmp (username, val[i].username, username_len) == 0) {
      *password = (uint8_t *) val[i].password;
      *password_len = val[i].password_len;
      stun_debug ("Found valid username, returning password : '%s'", *password);
      return TRUE;
    }
  }

  return FALSE;

}

StunValidationStatus stun_agent_validate (StunAgent *agent, StunMessage *msg,
    const uint8_t *buffer, size_t buffer_len,
    StunMessageIntegrityValidate validater, void * validater_data)
{
  StunTransactionId msg_id;
  uint32_t fpr;
  uint32_t crc32;
  int len;
  uint8_t *username = NULL;
  uint16_t username_len;
  uint8_t *key = NULL;
  size_t key_len;
  uint8_t *hash;
  uint8_t sha[20];
  uint16_t hlen;
  int sent_id_idx = -1;
  uint16_t unknown;
  int error_code;
  int ignore_credentials = 0;
  uint8_t long_term_key[16] = { 0 };
  bool long_term_key_valid = FALSE;

  len = stun_message_validate_buffer_length (buffer, buffer_len,
       !(agent->usage_flags & STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES));
  if (len == STUN_MESSAGE_BUFFER_INVALID) {
    return STUN_VALIDATION_NOT_STUN;
  } else if (len == STUN_MESSAGE_BUFFER_INCOMPLETE) {
    return STUN_VALIDATION_INCOMPLETE_STUN;
  } else if (len != (int) buffer_len) {
    return STUN_VALIDATION_NOT_STUN;
  }

  msg->buffer = (uint8_t *) buffer;
  msg->buffer_len = buffer_len;
  msg->agent = agent;
  msg->key = NULL;
  msg->key_len = 0;
  msg->long_term_valid = FALSE;

  /* TODO: reject it or not ? */
  if ((agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
          agent->compatibility == STUN_COMPATIBILITY_WLM2009) &&
      !stun_message_has_cookie (msg)) {
      stun_debug ("STUN demux error: no cookie!");
      return STUN_VALIDATION_BAD_REQUEST;
  }

  if ((agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
          agent->compatibility == STUN_COMPATIBILITY_WLM2009) &&
      agent->usage_flags & STUN_AGENT_USAGE_USE_FINGERPRINT) {
    /* Looks for FINGERPRINT */
    if (stun_message_find32 (msg, STUN_ATTRIBUTE_FINGERPRINT, &fpr) !=
        STUN_MESSAGE_RETURN_SUCCESS) {
      stun_debug ("STUN demux error: no FINGERPRINT attribute!");
      return STUN_VALIDATION_BAD_REQUEST;
    }
    /* Checks FINGERPRINT */
    crc32 = stun_fingerprint (msg->buffer, stun_message_length (msg),
        agent->compatibility == STUN_COMPATIBILITY_WLM2009);
    fpr = ntohl (fpr);
    if (fpr != crc32) {
      stun_debug ("STUN demux error: bad fingerprint: 0x%08x,"
          " expected: 0x%08x!", fpr, crc32);
      return STUN_VALIDATION_BAD_REQUEST;
    }

    stun_debug ("STUN demux: OK!");
  }

  if (stun_message_get_class (msg) == STUN_RESPONSE ||
      stun_message_get_class (msg) == STUN_ERROR) {
    stun_message_id (msg, msg_id);
    for (sent_id_idx = 0; sent_id_idx < STUN_AGENT_MAX_SAVED_IDS; sent_id_idx++) {
      if (agent->sent_ids[sent_id_idx].valid == TRUE &&
          agent->sent_ids[sent_id_idx].method == stun_message_get_method (msg) &&
          memcmp (msg_id, agent->sent_ids[sent_id_idx].id,
              sizeof(StunTransactionId)) == 0) {

        key = agent->sent_ids[sent_id_idx].key;
        key_len = agent->sent_ids[sent_id_idx].key_len;
        memcpy (long_term_key, agent->sent_ids[sent_id_idx].long_term_key,
            sizeof(long_term_key));
        long_term_key_valid = agent->sent_ids[sent_id_idx].long_term_valid;
        break;
      }
    }
    if (sent_id_idx == STUN_AGENT_MAX_SAVED_IDS) {
      return STUN_VALIDATION_UNMATCHED_RESPONSE;
    }
  }

  ignore_credentials =
      (agent->usage_flags & STUN_AGENT_USAGE_IGNORE_CREDENTIALS) ||
      (stun_message_get_class (msg) == STUN_ERROR &&
       stun_message_find_error (msg, &error_code) ==
          STUN_MESSAGE_RETURN_SUCCESS &&
       (error_code == 400 || error_code == 401 || error_code == 438)) ||
      (stun_message_get_class (msg) == STUN_INDICATION &&
          (agent->usage_flags & STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS ||
              agent->usage_flags & STUN_AGENT_USAGE_NO_INDICATION_AUTH));

  if (key == NULL &&
      ignore_credentials == 0 &&
      (stun_message_get_class (msg) == STUN_REQUEST ||
       stun_message_get_class (msg) == STUN_INDICATION) &&
      (((agent->usage_flags & STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS) &&
       (!stun_message_has_attribute (msg, STUN_ATTRIBUTE_USERNAME) ||
        !stun_message_has_attribute (msg, STUN_ATTRIBUTE_MESSAGE_INTEGRITY))) ||
      ((agent->usage_flags & STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS) &&
        stun_message_get_class (msg) == STUN_REQUEST &&
        (!stun_message_has_attribute (msg, STUN_ATTRIBUTE_USERNAME) ||
         !stun_message_has_attribute (msg, STUN_ATTRIBUTE_MESSAGE_INTEGRITY) ||
         !stun_message_has_attribute (msg, STUN_ATTRIBUTE_NONCE) ||
         !stun_message_has_attribute (msg, STUN_ATTRIBUTE_REALM))) ||
       ((agent->usage_flags & STUN_AGENT_USAGE_IGNORE_CREDENTIALS) == 0 &&
         stun_message_has_attribute (msg, STUN_ATTRIBUTE_USERNAME) &&
         !stun_message_has_attribute (msg, STUN_ATTRIBUTE_MESSAGE_INTEGRITY)))) {
        return STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST;
  }

  if (stun_message_has_attribute (msg, STUN_ATTRIBUTE_MESSAGE_INTEGRITY) &&
      ((key == NULL && ignore_credentials == 0) ||
          (agent->usage_flags & STUN_AGENT_USAGE_FORCE_VALIDATER))) {
    username_len = 0;
    username = (uint8_t *) stun_message_find (msg, STUN_ATTRIBUTE_USERNAME,
        &username_len);
    if (validater == NULL ||
        validater (agent, msg, username, username_len,
            &key, &key_len, validater_data) == FALSE) {
      return STUN_VALIDATION_UNAUTHORIZED;
    }
  }

  if (ignore_credentials == 0 && key != NULL && key_len > 0) {
    hash = (uint8_t *) stun_message_find (msg,
        STUN_ATTRIBUTE_MESSAGE_INTEGRITY, &hlen);

    if (hash) {
      /* We must give the size from start to the end of the attribute
         because you might have a FINGERPRINT attribute after it... */
      if (agent->usage_flags & STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS) {
        uint8_t *realm = NULL;
        uint16_t realm_len;
        uint8_t md5[16];

        if (long_term_key_valid) {
          memcpy (md5, long_term_key, sizeof (md5));
        } else {
          realm = (uint8_t *) stun_message_find (msg,  STUN_ATTRIBUTE_REALM, &realm_len);
          username = (uint8_t *) stun_message_find (msg,
              STUN_ATTRIBUTE_USERNAME, &username_len);
          if (username == NULL || realm == NULL) {
            return STUN_VALIDATION_UNAUTHORIZED;
          }
          stun_hash_creds (realm, realm_len,
              username,  username_len,
              key, key_len, md5);
        }

        memcpy (msg->long_term_key, md5, sizeof(md5));
        msg->long_term_valid = TRUE;

        if (agent->compatibility == STUN_COMPATIBILITY_RFC3489 ||
            agent->compatibility == STUN_COMPATIBILITY_OC2007) {
          stun_sha1 (msg->buffer, hash + 20 - msg->buffer, hash - msg->buffer,
              sha, md5, sizeof(md5), TRUE);
        } else if (agent->compatibility == STUN_COMPATIBILITY_WLM2009) {
          stun_sha1 (msg->buffer, hash + 20 - msg->buffer,
              stun_message_length (msg) - 20, sha, md5, sizeof(md5), TRUE);
        } else {
          stun_sha1 (msg->buffer, hash + 20 - msg->buffer,
              hash - msg->buffer, sha, md5, sizeof(md5), FALSE);
        }
      } else {
        if (agent->compatibility == STUN_COMPATIBILITY_RFC3489 ||
            agent->compatibility == STUN_COMPATIBILITY_OC2007) {
          stun_sha1 (msg->buffer, hash + 20 - msg->buffer, hash - msg->buffer,
              sha, key, key_len, TRUE);
        } else if (agent->compatibility == STUN_COMPATIBILITY_WLM2009) {
          stun_sha1 (msg->buffer, hash + 20 - msg->buffer,
              stun_message_length (msg) - 20, sha, key, key_len, TRUE);
        } else {
          stun_sha1 (msg->buffer, hash + 20 - msg->buffer,
              hash - msg->buffer, sha, key, key_len, FALSE);
        }
      }

      stun_debug (" Message HMAC-SHA1 fingerprint:");
      stun_debug_bytes ("  key     : ", key, key_len);
      stun_debug_bytes ("  expected: ", sha, sizeof (sha));
      stun_debug_bytes ("  received: ", hash, sizeof (sha));

      if (memcmp (sha, hash, sizeof (sha)))  {
        stun_debug ("STUN auth error: SHA1 fingerprint mismatch!");
        return STUN_VALIDATION_UNAUTHORIZED;
      }

      stun_debug ("STUN auth: OK!");
      msg->key = key;
      msg->key_len = key_len;
    } else if (!(stun_message_get_class (msg) == STUN_ERROR &&
        stun_message_find_error (msg, &error_code) ==
            STUN_MESSAGE_RETURN_SUCCESS &&
        (error_code == 400 || error_code == 401))) {
      stun_debug ("STUN auth error: No message integrity attribute!");
      return STUN_VALIDATION_UNAUTHORIZED;
    }
  }


  if (sent_id_idx != -1 && sent_id_idx < STUN_AGENT_MAX_SAVED_IDS) {
    agent->sent_ids[sent_id_idx].valid = FALSE;
  }

  if (stun_agent_find_unknowns (agent, msg, &unknown, 1) > 0) {
    if (stun_message_get_class (msg) == STUN_REQUEST)
      return STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE;
    else
      return STUN_VALIDATION_UNKNOWN_ATTRIBUTE;
  }
  return STUN_VALIDATION_SUCCESS;

}

bool stun_agent_forget_transaction (StunAgent *agent, StunTransactionId id)
{
  int i;

  for (i = 0; i < STUN_AGENT_MAX_SAVED_IDS; i++) {
    if (agent->sent_ids[i].valid == TRUE &&
        memcmp (id, agent->sent_ids[i].id,
            sizeof(StunTransactionId)) == 0) {
      agent->sent_ids[i].valid = FALSE;
      return TRUE;
    }
  }

  return FALSE;
}

bool stun_agent_init_request (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, StunMethod m)
{
  bool ret;
  StunTransactionId id;

  msg->buffer = buffer;
  msg->buffer_len = buffer_len;
  msg->agent = agent;
  msg->key = NULL;
  msg->key_len = 0;
  msg->long_term_valid = FALSE;

  stun_make_transid (id);

  ret = stun_message_init (msg, STUN_REQUEST, m, id);

  if (ret) {
    if (agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
        agent->compatibility == STUN_COMPATIBILITY_WLM2009) {
      uint32_t cookie = htonl (STUN_MAGIC_COOKIE);
      memcpy (msg->buffer + STUN_MESSAGE_TRANS_ID_POS, &cookie, sizeof (cookie));
    }
    if ((agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
            agent->compatibility == STUN_COMPATIBILITY_WLM2009) &&
        (agent->software_attribute != NULL ||
            agent->usage_flags & STUN_AGENT_USAGE_ADD_SOFTWARE)) {
      stun_message_append_software (msg, agent->software_attribute);
    }
  }

  return ret;
}


bool stun_agent_init_indication (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, StunMethod m)
{
  bool ret;
  StunTransactionId id;

  msg->buffer = buffer;
  msg->buffer_len = buffer_len;
  msg->agent = agent;
  msg->key = NULL;
  msg->key_len = 0;
  msg->long_term_valid = FALSE;

  stun_make_transid (id);
  ret = stun_message_init (msg, STUN_INDICATION, m, id);

  if (ret) {
    if (agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
        agent->compatibility == STUN_COMPATIBILITY_WLM2009) {
      uint32_t cookie = htonl (STUN_MAGIC_COOKIE);
      memcpy (msg->buffer + STUN_MESSAGE_TRANS_ID_POS, &cookie, sizeof (cookie));
    }
  }

  return ret;
}


bool stun_agent_init_response (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, const StunMessage *request)
{

  StunTransactionId id;

  if (stun_message_get_class (request) != STUN_REQUEST) {
    return FALSE;
  }

  msg->buffer = buffer;
  msg->buffer_len = buffer_len;
  msg->agent = agent;
  msg->key = request->key;
  msg->key_len = request->key_len;
  memmove (msg->long_term_key, request->long_term_key,
      sizeof(msg->long_term_key));
  msg->long_term_valid = request->long_term_valid;

  stun_message_id (request, id);

  if (stun_message_init (msg, STUN_RESPONSE,
          stun_message_get_method (request), id)) {

    if ((agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
            agent->compatibility == STUN_COMPATIBILITY_WLM2009) &&
        (agent->software_attribute != NULL ||
            agent->usage_flags & STUN_AGENT_USAGE_ADD_SOFTWARE)) {
      stun_message_append_software (msg, agent->software_attribute);
    }
    return TRUE;
  }
  return FALSE;
}


bool stun_agent_init_error (StunAgent *agent, StunMessage *msg,
    uint8_t *buffer, size_t buffer_len, const StunMessage *request,
    StunError err)
{
  StunTransactionId id;

  if (stun_message_get_class (request) != STUN_REQUEST) {
    return FALSE;
  }

  msg->buffer = buffer;
  msg->buffer_len = buffer_len;
  msg->agent = agent;
  msg->key = request->key;
  msg->key_len = request->key_len;
  memmove (msg->long_term_key, request->long_term_key,
      sizeof(msg->long_term_key));
  msg->long_term_valid = request->long_term_valid;

  stun_message_id (request, id);


  if (stun_message_init (msg, STUN_ERROR,
          stun_message_get_method (request), id)) {

    if ((agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
            agent->compatibility == STUN_COMPATIBILITY_WLM2009) &&
        (agent->software_attribute != NULL ||
            agent->usage_flags & STUN_AGENT_USAGE_ADD_SOFTWARE)) {
      stun_message_append_software (msg, agent->software_attribute);
    }
    if (stun_message_append_error (msg, err) == STUN_MESSAGE_RETURN_SUCCESS) {
      return TRUE;
    }
  }
  return FALSE;
}


size_t stun_agent_build_unknown_attributes_error (StunAgent *agent,
    StunMessage *msg, uint8_t *buffer, size_t buffer_len,
    const StunMessage *request)
{

  unsigned counter;
  uint16_t ids[STUN_AGENT_MAX_UNKNOWN_ATTRIBUTES];

  counter = stun_agent_find_unknowns (agent, request,
      ids, STUN_AGENT_MAX_UNKNOWN_ATTRIBUTES);

  if (stun_agent_init_error (agent, msg, buffer, buffer_len,
          request, STUN_ERROR_UNKNOWN_ATTRIBUTE) == FALSE) {
    return 0;
  }

  /* NOTE: Old RFC3489 compatibility:
   * When counter is odd, duplicate one value for 32-bits padding. */
  if (!stun_message_has_cookie (request) && (counter & 1))
    ids[counter++] = ids[0];

  if (stun_message_append_bytes (msg, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
          ids, counter * 2) == STUN_MESSAGE_RETURN_SUCCESS) {
    return stun_agent_finish_message (agent, msg, request->key, request->key_len);
  }

  return 0;
}


size_t stun_agent_finish_message (StunAgent *agent, StunMessage *msg,
    const uint8_t *key, size_t key_len)
{
  uint8_t *ptr;
  uint32_t fpr;
  int saved_id_idx = 0;
  uint8_t md5[16];

  if (stun_message_get_class (msg) == STUN_REQUEST) {
    for (saved_id_idx = 0; saved_id_idx < STUN_AGENT_MAX_SAVED_IDS; saved_id_idx++) {
      if (agent->sent_ids[saved_id_idx].valid == FALSE) {
        break;
      }
    }
  }
  if (saved_id_idx == STUN_AGENT_MAX_SAVED_IDS) {
    stun_debug ("WARNING: Saved IDs full. STUN message dropped.");
    return 0;
  }

  if (msg->key != NULL) {
    key = msg->key;
    key_len = msg->key_len;
  }

  if (key != NULL) {
    bool skip = FALSE;

    if (msg->long_term_valid) {
      memcpy (md5, msg->long_term_key, sizeof(msg->long_term_key));
    } else if (agent->usage_flags & STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS) {
      uint8_t *realm = NULL;
      uint8_t *username = NULL;
      uint16_t realm_len;
      uint16_t username_len;

      realm = (uint8_t *) stun_message_find (msg,
          STUN_ATTRIBUTE_REALM, &realm_len);
      username = (uint8_t *) stun_message_find (msg,
          STUN_ATTRIBUTE_USERNAME, &username_len);
      if (username == NULL || realm == NULL) {
        skip = TRUE;
      } else {
        stun_hash_creds (realm, realm_len,
            username,  username_len,
            key, key_len, md5);
        memcpy (msg->long_term_key, md5, sizeof(msg->long_term_key));
        msg->long_term_valid = TRUE;
      }
    }

    /* If no realm/username and long term credentials,
       then don't send the message integrity */
    if (skip == FALSE) {
      ptr = stun_message_append (msg, STUN_ATTRIBUTE_MESSAGE_INTEGRITY, 20);
      if (ptr == NULL) {
        return 0;
      }
      if (agent->usage_flags & STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS) {
        if (agent->compatibility == STUN_COMPATIBILITY_RFC3489 ||
            agent->compatibility == STUN_COMPATIBILITY_OC2007) {
          stun_sha1 (msg->buffer, stun_message_length (msg),
              stun_message_length (msg) - 20, ptr, md5, sizeof(md5), TRUE);
        } else if (agent->compatibility == STUN_COMPATIBILITY_WLM2009) {
          size_t minus = 20;
          if (agent->usage_flags & STUN_AGENT_USAGE_USE_FINGERPRINT)
            minus -= 8;

          stun_sha1 (msg->buffer, stun_message_length (msg),
              stun_message_length (msg) - minus, ptr, md5, sizeof(md5), TRUE);
        } else {
          stun_sha1 (msg->buffer, stun_message_length (msg),
              stun_message_length (msg) - 20, ptr, md5, sizeof(md5), FALSE);
        }
      } else {
        if (agent->compatibility == STUN_COMPATIBILITY_RFC3489 ||
            agent->compatibility == STUN_COMPATIBILITY_OC2007) {
          stun_sha1 (msg->buffer, stun_message_length (msg),
              stun_message_length (msg) - 20, ptr, key, key_len, TRUE);
        } else if (agent->compatibility == STUN_COMPATIBILITY_WLM2009) {
          size_t minus = 20;
          if (agent->usage_flags & STUN_AGENT_USAGE_USE_FINGERPRINT)
            minus -= 8;

          stun_sha1 (msg->buffer, stun_message_length (msg),
              stun_message_length (msg) - minus, ptr, key, key_len, TRUE);
        } else {
          stun_sha1 (msg->buffer, stun_message_length (msg),
              stun_message_length (msg) - 20, ptr, key, key_len, FALSE);
        }
      }

      stun_debug (" Message HMAC-SHA1 message integrity:");
      stun_debug_bytes ("  key     : ", key, key_len);
      stun_debug_bytes ("  sent    : ", ptr, 20);
    }
  }

  if ((agent->compatibility == STUN_COMPATIBILITY_RFC5389 ||
          agent->compatibility == STUN_COMPATIBILITY_WLM2009) &&
      agent->usage_flags & STUN_AGENT_USAGE_USE_FINGERPRINT) {
    ptr = stun_message_append (msg, STUN_ATTRIBUTE_FINGERPRINT, 4);
    if (ptr == NULL) {
      return 0;
    }

    fpr = stun_fingerprint (msg->buffer, stun_message_length (msg),
        agent->compatibility == STUN_COMPATIBILITY_WLM2009);
    memcpy (ptr, &fpr, sizeof (fpr));

    stun_debug_bytes (" Message HMAC-SHA1 fingerprint: ", ptr, 4);
  }


  if (stun_message_get_class (msg) == STUN_REQUEST) {
    stun_message_id (msg, agent->sent_ids[saved_id_idx].id);
    agent->sent_ids[saved_id_idx].method = stun_message_get_method (msg);
    agent->sent_ids[saved_id_idx].key = (uint8_t *) key;
    agent->sent_ids[saved_id_idx].key_len = key_len;
    memcpy (agent->sent_ids[saved_id_idx].long_term_key, msg->long_term_key,
        sizeof(msg->long_term_key));
    agent->sent_ids[saved_id_idx].long_term_valid = msg->long_term_valid;
    agent->sent_ids[saved_id_idx].valid = TRUE;
  }

  msg->key = (uint8_t *) key;
  msg->key_len = key_len;
  return stun_message_length (msg);

}

static bool stun_agent_is_unknown (StunAgent *agent, uint16_t type)
{

  uint16_t *known_attr = agent->known_attributes;

  while(*known_attr != 0) {
    if (*known_attr == type) {
      return FALSE;
    }
    known_attr++;
  }

  return TRUE;

}


static unsigned
stun_agent_find_unknowns (StunAgent *agent, const StunMessage * msg,
    uint16_t *list, unsigned max)
{
  unsigned count = 0;
  uint16_t len = stun_message_length (msg);
  size_t offset = 0;

  offset = STUN_MESSAGE_ATTRIBUTES_POS;

  while ((offset < len) && (count < max))
  {
    size_t alen = stun_getw (msg->buffer + offset + STUN_ATTRIBUTE_TYPE_LEN);
    uint16_t atype = stun_getw (msg->buffer + offset);

    if (!stun_optional (atype) && stun_agent_is_unknown (agent, atype))
    {
      stun_debug ("STUN unknown: attribute 0x%04x(%u bytes)",
           (unsigned)atype, (unsigned)alen);
      list[count++] = htons (atype);
    }

    if (!(agent->usage_flags & STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES))
      alen = stun_align (alen);

    offset += STUN_ATTRIBUTE_VALUE_POS + alen;
  }

  stun_debug ("STUN unknown: %u mandatory attribute(s)!", count);
  return count;
}

void stun_agent_set_software (StunAgent *agent, const char *software)
{
  agent->software_attribute = software;
}
