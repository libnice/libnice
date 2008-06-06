/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
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

#ifndef STUN_MSG_H
# define STUN_MSG_H 1

/**
 * @file stun-msg.h
 * @brief STUN low-level message formatting and parsing
 */



# include <stdint.h>
# include <sys/types.h>
# include <stdbool.h>


# define STUN_MAXMSG 65552 /* bytes */
# define STUN_MAXCHR 127u
# define STUN_MAXSTR ((STUN_MAXCHR * 6u) + 1)




#include "utils.h"
#include "stun3489bis.h"
#include "stunhmac.h"

# ifndef NDEBUG
#  include <stdio.h>
#  include <stdarg.h>
#  define DBG stun_debug
#  define DBG_bytes stun_debug_bytes
# else
#  define DBG( ... ) (void)0
#  define DBG_bytes( data, len ) (void)0
# endif



# ifdef __cplusplus
extern "C" {
# endif


int stun_xor_address (const uint8_t *msg,
                      struct sockaddr *addr, socklen_t addrlen);

/**
 * @section stunrecv
 * @brief STUN message processing functions
 */

# ifndef STUN_VALIDATE_DECLARATION
#  define STUN_VALIDATE_DECLARATION 1
/**
 * Verifies that a packet is a valid STUN message.
 *
 * @return actual byte length of the message if valid (>0),
 * 0 if it the packet is incomplete or -1 in case of other error.
 */
ssize_t stun_validate (const uint8_t *msg, size_t len);

/**
 * Checks whether a packet on a mutiplexed STUN/non-STUN channel looks like a
 * STUN message. It is assumed that stun_validate succeeded first (i.e.
 * returned a stricly positive value).
 *
 * @return true if STUN message with cookie and fingerprint, 0 otherwise.
 */
bool stun_demux (const uint8_t *msg);

#endif

/**
 * Matches a response (or error response) to a request.
 *
 * @param msg valid STUN message
 * @param method STUN method number (host byte order)
 * @param id STUN transaction id
 * @param key HMAC key, or NULL if there is no authentication
 * @param keylen HMAC key byte length, 0 is no authentication
 * @param error [OUT] set to -1 if the response is not an error,
 * to the error code if it is an error response.
 *
 * @return true if and only if the message is a response or an error response
 * with the STUN cookie and specified method and transaction identifier.
 */
bool stun_match_messages (const uint8_t *restrict resp,
                          const uint8_t *restrict req,
                          const uint8_t *key, size_t keylen,
                          int *restrict error);
int stun_verify_key (const uint8_t *msg, const void *key, size_t keylen);
int stun_verify_password (const uint8_t *msg, const char *pw);
  int stun_verify_username (const uint8_t *msg, const char *local_ufrag, uint32_t compat);

/**
 * Compares the length and content of an attribute.
 *
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param data pointer to value to compare with
 * @param len byte length of the value
 * @return 0 in case of match, ENOENT if attribute was not found,
 * EINVAL if it did not match (different length, or same length but
 * different content)
 */
int stun_memcmp (const uint8_t *msg, stun_attr_type_t type,
                 const void *data, size_t len);

/**
 * Compares the content of an attribute with a string.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param str string to compare with
 * @return 0 in case of match, ENOENT if attribute was not found,
 * EINVAL if it did not match
 */
int stun_strcmp (const uint8_t *msg, stun_attr_type_t type,
                 const char *str);

/**
 * @param type host-byte order STUN attribute type
 *
 * @return true if @a type is an attribute type unknown to this library
 * (regardless of being a mandatory or optional attribute type)
 */
bool stun_is_unknown (uint16_t type);

/**
 * Looks for unknown mandatory attributes in a valid STUN message.
 * @param msg valid STUN message
 * @param list [OUT] table pointer to store unknown attributes IDs
 * @param max size of the table in units of uint16_t
 * @return the number of unknown mandatory attributes up to max.
 */
unsigned stun_find_unknown (const uint8_t *msg, uint16_t *list, unsigned max);

/**
 * @section stunsend
 * @brief Message formatting functions
 */

/**
 * Initializes a STUN request message buffer, with no attributes.
 * @param m STUN message method (host byte order)
 */
void stun_init_request (uint8_t *msg, stun_method_t m);

/**
 * Initializes a STUN indication message buffer, with no attributes.
 * @param m STUN message method (host byte order)
 */
void stun_init_indication (uint8_t *msg, stun_method_t m);

/**
 * Initializes a STUN message buffer with a SERVER attribute (if there is
 * enough room for it), in response to a given valid STUN request messsage.
 * STUN method and transaction ID are copied from the request message.
 *
 * @param ans [OUT] STUN message buffer
 * @param msize STUN message buffer size
 * @param req STUN message query
 *
 * ans == req is allowed.
 */
void stun_init_response (uint8_t *ans, size_t msize, const uint8_t *req, int compat);

/**
 * Initializes a STUN error response message buffer with an ERROR-CODE
 * and a SERVER attributes, in response to a given valid STUN request
 * messsage. STUN method and transaction ID are copied from the request
 * message.
 *
 * @param ans [OUT] STUN message buffer
 * @param msize STUN message buffer size
 * @param req STUN message to copy method and transaction ID from
 * @param err host-byte order STUN integer error code
 *
 * @return 0 on success, ENOBUFS on error
 *
 * ans == req is allowed.
 */
int stun_init_error (uint8_t *ans,  size_t msize, const uint8_t *req,
                     stun_error_t err, int compat);

/**
 * Initializes a STUN error response message buffer, in response to a valid
 * STUN request messsage with unknown attributes. STUN method, transaction ID
 * and unknown attribute IDs are copied from the request message.
 *
 * @param ans [OUT] STUN message buffer
 * @param msize STUN message buffer size
 * @param req STUN request message
 * @return 0 on success, ENOBUFS otherwise
 *
 * ans == req is allowed.
 */
int stun_init_error_unknown (uint8_t *ans, size_t msize, const uint8_t *req,
                             int compat);

size_t
stun_finish_long (uint8_t *msg, size_t *restrict plen,
                  const char *realm, const char *username, const char *nonce,
                  const void *restrict key, size_t keylen, int compat);

/**
 * Completes a STUN message structure before sending it, and
 * authenticates it with short-term credentials.
 * No further attributes shall be added.
 *
 * @param msg STUN message buffer
 * @param plen [IN/OUT] buffer size on entry, message length on return
 * @param username nul-terminated STUN username (or NULL if none)
 * @param password nul-terminated STUN secret password (or NULL if none)
 * @param nonce STUN authentication nonce (or NULL if none)
 *
 * @return 0 on success, ENOBUFS on error.
 */
size_t stun_finish_short (uint8_t *msg, size_t *restrict plen,
                          const char *username, const char *password,
                          const char *nonce, int compat);

/**
 * Completes a STUN message structure before sending it.
 * No further attributes shall be added.
 *
 * @param msg STUN message buffer
 * @param plen [IN/OUT] buffer size on entry, message length on return
 *
 * @return 0 on success, ENOBUFS on error.
 */
size_t stun_finish (uint8_t *restrict msg, size_t *restrict plen, int compat);


# ifdef __cplusplus
}
# endif


#endif
