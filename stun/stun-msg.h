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


# ifndef NDEBUG
#  include <stdio.h>
#  include <stdarg.h>
static inline void DBG (const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
}
# else
#  define DBG( ... ) (void)0
# endif

# include <stdint.h>
# include <sys/types.h>
# include <stdbool.h>

# define STUN_MAXMSG 65552 /* bytes */

# define STUN_COOKIE 0x2112A442
# define STUN_COOKIE_BYTES 0x21, 0x12, 0xA4, 0x42

typedef struct stun_hdr_s
{
	uint16_t  msg_type;
	uint16_t  msg_len;
	uint32_t  msg_cookie;
	uint32_t  msg_id[3];
} stun_hdr_t;


typedef uint8_t stun_msg_t[STUN_MAXMSG];

/* Message classes */
typedef enum
{
	STUN_REQUEST=0,
	STUN_INDICATION=1,
	STUN_RESPONSE=2,
	STUN_ERROR=3
} stun_class_t;

/* Message methods */
typedef enum
{
	STUN_BINDING=0x001,		/* RFC3489bis-07 */
	STUN_OLD_SHARED_SECRET=0x002,	/* old RFC3489 */
	STUN_ALLOCATE=0x003		/* ?? TURN */
} stun_method_t;

/* Attribute types */
typedef enum
{
	/* Mandatory attributes */
	STUN_MAPPED_ADDRESS=0x0001,		/* RFC3489bis-07 */
	STUN_OLD_RESPONSE_ADDRESS=0x0002,	/* old RFC3489 */
	STUN_OLD_CHANGE_REQUEST=0x0003,		/* old RFC3489 */
	STUN_OLD_SOURCE_ADDRESS=0x0004,		/* old RFC3489 */
	STUN_OLD_CHANGED_ADDRESS=0x0005,	/* old RFC3489 */
	STUN_USERNAME=0x0006,			/* RFC3489bis-07 */
	STUN_OLD_PASSWORD=0x0007,		/* old RFC3489 */
	STUN_MESSAGE_INTEGRITY=0x0008,		/* RFC3489bis-07 */
	STUN_ERROR_CODE=0x0009,			/* RFC3489bis-07 */
	STUN_UNKNOWN_ATTRIBUTES=0x000A,		/* RFC3489bis-07 */
	STUN_OLD_REFLECTED_FROM=0x000B,		/* old RFC3489 */

	STUN_REALM=0x0014,			/* RFC3489bis-07 */
	STUN_NONCE=0x0015,			/* RFC3489bis-07 */
	STUN_REQUESTED_ADDRESS_TYPE=0x0017,	/* TURN-IPv6-03 */

	STUN_XOR_MAPPED_ADDRESS=0x0020,		/* RFC3489bis-07 */

	STUN_PRIORITY=0x0024,			/* ICE-15 */
	STUN_USE_CANDIDATE=0x0025,		/* ICE-15 */

	/* Optional attributes */
	STUN_SERVER=0x8022,			/* RFC3489bis-07 */
	STUN_ALTERNATE_SERVER=0x8023,		/* RFC3489bis-07 */
	STUN_REFRESH_INTERVAL=0x8024,		/* RFC3489bis-07 */

	STUN_FINGERPRINT=0x8028,		/* RFC3489bis-07 */
	STUN_ICE_CONTROLLED=0x8029,		/* ICE-15 */
	STUN_ICE_CONTROLLING=0x802A		/* ICE-15 */
} stun_attr_type_t;


static inline int stun_optional (stun_attr_type_t t)
{
	return t >> 15;
}

typedef uint8_t stun_transid_t[12];

/* Error codes */
typedef enum
{
	STUN_TRY_ALTERNATE=300,
	STUN_BAD_REQUEST=400,
	STUN_UNAUTHORIZED=401,
	STUN_UNKNOWN_ATTRIBUTE=420,
	STUN_STALE_CREDENTIALS=430,
	STUN_INTEGRITY_CHECK_FAILURE=431,
	STUN_MISSING_USERNAME=432,
	STUN_USE_TLS=433,
	STUN_MISSING_REALM=434,
	STUN_MISSING_NONCE=435,
	STUN_UNKNOWN_USERNAME=436,
	STUN_STALE_NONCE=438,
	STUN_ROLE_CONFLICT=487,
	STUN_SERVER_ERROR=500,
	STUN_GLOBAL_FAILURE=600
} stun_error_t;


/**
 * @return complement to the next multiple of 4.
 */
static inline size_t stun_padding (size_t l)
{
	return (4 - (l & 3)) & 3;
}


/**
 * Rounds up an integer to the next multiple of 4.
 */
static inline size_t stun_align (size_t l)
{
	return (l + 3) & ~3;
}


/**
 * Reads a word from a non-aligned buffer.
 * @return host byte order word value.
 */
static inline uint16_t stun_getw (const uint8_t *ptr)
{
	return ((ptr)[0] << 8) | ptr[1];
}

static inline uint16_t stun_length (const uint8_t *ptr)
{
	return stun_getw (ptr + 2);
}


/**
 * @return STUN message class in host byte order (value from 0 to 3)
 */
static inline stun_class_t stun_get_class (const uint8_t *msg)
{
	uint16_t t = stun_getw (msg);
	return (stun_class_t)(((t & 0x0100) >> 7) | ((t & 0x0010) >> 4));
}

/**
 * @return STUN message method (value from 0 to 0xfff)
 */
static inline stun_method_t stun_get_method (const uint8_t *msg)
{
	uint16_t t = stun_getw (msg);
	return (stun_method_t)(((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) |
	                        (t & 0x000f));
}

/**
 * @return STUN message transaction ID
 */
static inline const uint8_t *stun_id (const uint8_t *msg)
{
	//assert (stun_valid (req));
	return msg + 8;
}


# ifdef __cplusplus
extern "C" {
# endif

uint32_t stun_fingerprint (const uint8_t *msg);
void stun_sha1 (const uint8_t *msg, uint8_t *sha,
                const void *key, size_t keylen);

/**
 * Generates a pseudo-random secure STUN transaction ID.
 */
void stun_make_transid (stun_transid_t id);

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
#endif

/**
 * Checks whether a packet on a mutiplexed STUN/non-STUN channel looks like a
 * STUN message. It is assumed that stun_validate succeeded first (i.e.
 * returned a stricly positive value).
 *
 * @return true if STUN message with cookie and fingerprint, 0 otherwise.
 */
bool stun_demux (const uint8_t *msg);

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


/**
 * Checks if an attribute is present within a STUN message.
 *
 * @param msg valid STUN message
 * @param type STUN attribute type (host byte order)
 *
 * @return whether there is a MESSAGE-INTEGRITY attribute
 */
bool stun_present (const uint8_t *msg, stun_attr_type_t type);

/**
 * Looks for a flag attribute within a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @return 0 if flag is present, ENOENT if it is not, EINVAL if flag payload
 * size is not zero.
 */
int stun_find_flag (const uint8_t *msg, stun_attr_type_t type);

/**
 * Extracts a 32-bits attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param pval [OUT] where to store the host byte ordered value
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload was not 32-bits.
 */
int stun_find32 (const uint8_t *msg, stun_attr_type_t type, uint32_t *pval);

/**
 * Extracts a 64-bits attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param pval [OUT] where to store the host byte ordered value
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload was not 64-bits.
 */
int stun_find64 (const uint8_t *msg, stun_attr_type_t type, uint64_t *pval);

/**
 * Extracts a string from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param buf buffer to store the extracted string
 * @param buflen byte length of @a buf
 *
 * @return number of characters (not including terminating nul) that would
 * have been written to @a buf if @a buflen were big enough (if the return
 * value is strictly smaller than @a buflen then the call was successful);
 * -1 if the specified attribute could not be found.
 *
 * @note A nul-byte is appended at the end (unless the buffer is not big
 * enough). However this function does not check for nul characters within
 * the extracted string; the caller is responsible for ensuring that the
 * extracted string does not contain any "illegal" bytes sequence (nul bytes
 * or otherwise, depending on the context).
 */
ssize_t stun_find_string (const uint8_t *restrict msg, stun_attr_type_t type,
                          char *buf, size_t buflen);


/**
 * Extracts a network address attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param addr [OUT] where to store the socket address
 * @param addrlen [IN/OUT] pointer to the size of the socket address
 * buffer upon entry, set to the length of the extracted socket
 * address upon return,
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload size was wrong or addrlen too small,
 * EAFNOSUPPORT if address family is unknown.
 */
int stun_find_addr (const uint8_t *restrict msg, stun_attr_type_t type,
                    struct sockaddr *restrict addr,
                    socklen_t *restrict addrlen);

/**
 * Extracts an obfuscated network address attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param addr [OUT] where to store the socket address
 * @param addrlen [IN/OUT] pointer to the size of the socket address
 * buffer upon entry, set to the length of the extracted socket
 * address upon return,
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload size was wrong or addrlen too small,
 * EAFNOSUPPORT if address family is unknown.
 */
int stun_find_xor_addr (const uint8_t *restrict msg, stun_attr_type_t type,
                        struct sockaddr *restrict addr,
                        socklen_t *restrict addrlen);

int stun_memcmp (const uint8_t *restrict msg, stun_attr_type_t type,
                 const void *data, size_t len);
int stun_strcmp (const uint8_t *restrict msg, stun_attr_type_t type,
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
 * Initializes a STUN message buffer with no attributes,
 * in response to a given valid STUN request messsage.
 * STUN method and transaction ID are copied from the request message.
 *
 * @param ans [OUT] STUN message buffer
 * @param req STUN message query
 *
 * ans == req is allowed.
 */
void stun_init_response (uint8_t *ans, const uint8_t *req);

/**
 * Initializes a STUN error response message buffer with an ERROR-CODE
 * attribute, in response to a given valid STUN request messsage.
 * STUN method and transaction ID are copied from the request message.
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
                     stun_error_t err);

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
int stun_init_error_unknown (uint8_t *ans, size_t msize, const uint8_t *req);

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
 * @param noncelen STUN authentication once byte length
 * (ignored if nonce is NULL)
 *
 * @return 0 on success, ENOBUFS on error.
 */
size_t stun_finish_short (uint8_t *msg, size_t *restrict plen,
                          const char *username, const char *password,
                          const void *nonce, size_t noncelen);

/**
 * Completes a STUN message structure before sending it.
 * No further attributes shall be added.
 *
 * @param msg STUN message buffer
 * @param plen [IN/OUT] buffer size on entry, message length on return
 *
 * @return 0 on success, ENOBUFS on error.
 */
size_t stun_finish (uint8_t *restrict msg, size_t *restrict plen);

/**
 * Appends an empty ("flag") attribute to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
int stun_append_flag (uint8_t *msg, size_t msize, stun_attr_type_t type);

/**
 * Appends an attribute consisting of a 32-bits value to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param value payload (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
int stun_append32 (uint8_t *msg, size_t msize,
                   stun_attr_type_t type, uint32_t value);

/**
 * Appends an attribute consisting of a 64-bits value to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param value payload (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
int stun_append64 (uint8_t *msg, size_t msize,
                   stun_attr_type_t type, uint64_t value);

/**
 * Appends an attribute from a nul-terminated string.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param str nul-terminated string
 * @return 0 on success, ENOBUFS on error.
 */
int stun_append_string (uint8_t *restrict msg, size_t msize,
                        stun_attr_type_t type, const char *str);

/**
 * Appends an attribute consisting of a network address to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribyte type (host byte order)
 * @param addr socket address to convert into an attribute
 * @param addrlen byte length of socket address
 * @return 0 on success, ENOBUFS if the message buffer overflowed,
 * EAFNOSUPPORT is the socket address family is not supported,
 * EINVAL if the socket address length is too small w.r.t. the address family.
 */
int stun_append_addr (uint8_t *restrict msg, size_t msize,
                      stun_attr_type_t type,
                      const struct sockaddr *restrict addr,
                      socklen_t addrlen);

/**
 * Appends an attribute consisting of a xor'ed network address.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribyte type (host byte order)
 * @param addr socket address to convert into an attribute
 * @param addrlen byte length of socket address
 * @return 0 on success, ENOBUFS if the message buffer overflowed,
 * EAFNOSUPPORT is the socket address family is not supported,
 * EINVAL if the socket address length is too small w.r.t. the address family.
 */
int stun_append_xor_addr (uint8_t *restrict msg, size_t msize,
                          stun_attr_type_t type,
                          const struct sockaddr *restrict addr,
                          socklen_t addrlen);

# ifdef __cplusplus
}
# endif


/**
 * @param msg valid STUN message
 * @return true if there is at least one unknown mandatory attribute.
 */
static inline bool stun_has_unknown (const void *msg)
{
	uint16_t dummy;
	return stun_find_unknown (msg, &dummy, 1);
}


/**
 * @param msg valid STUN message
 * @return whether there is a MESSAGE-INTEGRITY attribute
 */
static inline bool stun_has_integrity (const uint8_t *msg)
{
	return stun_present (msg, STUN_MESSAGE_INTEGRITY);
}

#endif
