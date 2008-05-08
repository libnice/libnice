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

static inline void DBG_bytes (const void *data, size_t len)
{
  size_t i;

  DBG ("0x");
  for (i = 0; i < len; i++)
    DBG ("%02x", ((const unsigned char *)data)[i]);
}
# else
#  define DBG( ... ) (void)0
#  define DBG_bytes( data, len ) (void)0
# endif

# include <stdint.h>
# include <sys/types.h>
# include <stdbool.h>

# define STUN_MAXMSG 65552 /* bytes */
# define STUN_MAXCHR 127u
# define STUN_MAXSTR ((STUN_MAXCHR * 6u) + 1)

# define STUN_COOKIE 0x2112A442

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
  STUN_BINDING=0x001,    /* RFC3489bis-11 */
  STUN_OLD_SHARED_SECRET=0x002,  /* old RFC3489 */
  STUN_ALLOCATE=0x003,    /* TURN-04 */
  STUN_SET_ACTIVE_DST=0x004,  /* TURN-04 */
  STUN_CONNECT=0x005,    /* TURN-04 */
  STUN_IND_SEND=0x006,    /* TURN-04 */
  STUN_IND_DATA=0x007,    /* TURN-04 */
  STUN_IND_CONNECT_STATUS=0x008  /* TURN-04 */
} stun_method_t;

/**
 * STUN attribute types
 * Should be in sync with stun_is_unknown()
 */
typedef enum
{
  /* Mandatory attributes */
  /* 0x0000 */        /* reserved */
  STUN_MAPPED_ADDRESS=0x0001,    /* RFC3489bis-11 */
  STUN_OLD_RESPONSE_ADDRESS=0x0002,  /* old RFC3489 */
  STUN_OLD_CHANGE_REQUEST=0x0003,    /* old RFC3489 */
  STUN_OLD_SOURCE_ADDRESS=0x0004,    /* old RFC3489 */
  STUN_OLD_CHANGED_ADDRESS=0x0005,  /* old RFC3489 */
  STUN_USERNAME=0x0006,      /* RFC3489bis-11 */
  STUN_OLD_PASSWORD=0x0007,    /* old RFC3489 */
  STUN_MESSAGE_INTEGRITY=0x0008,    /* RFC3489bis-11 */
  STUN_ERROR_CODE=0x0009,      /* RFC3489bis-11 */
  STUN_UNKNOWN_ATTRIBUTES=0x000A,    /* RFC3489bis-11 */
  STUN_OLD_REFLECTED_FROM=0x000B,    /* old RFC3489 */
  /* 0x000C */        /* reserved */
  STUN_LIFETIME=0x000D,      /* TURN-04 */
  /* 0x000E */        /* reserved */
  /* 0x000F */        /* reserved */
  STUN_BANDWIDTH=0x0010,      /* TURN-04 */
  /* 0x0011 */        /* reserved */
  STUN_REMOTE_ADDRESS=0x0012,    /* TURN-04 */
  STUN_DATA=0x0013,      /* TURN-04 */
  STUN_REALM=0x0014,      /* RFC3489bis-11 */
  STUN_NONCE=0x0015,      /* RFC3489bis-11 */
  STUN_RELAY_ADDRESS=0x0016,    /* TURN-04 */
  STUN_REQUESTED_ADDRESS_TYPE=0x0017,  /* TURN-IPv6-03 */
  STUN_REQUESTED_PORT_PROPS=0x0018,  /* TURN-04 */
  STUN_REQUESTED_TRANSPORT=0x0019,  /* TURN-04 */
  /* 0x001A */        /* reserved */
  /* 0x001B */        /* reserved */
  /* 0x001C */        /* reserved */
  /* 0x001D */        /* reserved */
  /* 0x001E */        /* reserved */
  /* 0x001F */        /* reserved */
  STUN_XOR_MAPPED_ADDRESS=0x0020,    /* RFC3489bis-11 */
  STUN_TIMER_VAL=0x0021,      /* TURN-04 */
  STUN_REQUESTED_IP=0x0022,    /* TURN-04 */
  STUN_CONNECT_STAT=0x0023,    /* TURN-04 */
  STUN_PRIORITY=0x0024,      /* ICE-18 */
  STUN_USE_CANDIDATE=0x0025,    /* ICE-18 */
  /* 0x0026 */        /* reserved */
  /* 0x0027 */        /* reserved */
  /* 0x0028 */        /* reserved */
  STUN_XOR_INTERNAL_ADDRESS=0x0029, /* wing-nat-control-04 */
  /* 0x002A-0x7fff */      /* reserved */

  /* Optional attributes */
  /* 0x8000-0x8021 */      /* reserved */
  STUN_SERVER=0x8022,      /* RFC3489bis-11 */
  STUN_ALTERNATE_SERVER=0x8023,    /* RFC3489bis-11 */
  STUN_REFRESH_INTERVAL=0x8024,    /* wing-nat-control-04 */
  /* 0x8025 */        /* reserved */
  /* 0x8026 */        /* reserved */
  /* 0x8027 */        /* reserved */
  STUN_FINGERPRINT=0x8028,    /* RFC3489bis-11 */
  STUN_ICE_CONTROLLED=0x8029,    /* ICE-18 */
  STUN_ICE_CONTROLLING=0x802A,    /* ICE-18 */
  /* 0x802B-0xFFFF */      /* reserved */
} stun_attr_type_t;


static inline bool stun_optional (uint16_t t)
{
  return (t >> 15) == 1;
}

typedef uint8_t stun_transid_t[12];

/**
 * STUN error codes
 * Should be in sync with stun_strerror()
 */
typedef enum
{
  STUN_TRY_ALTERNATE=300,      /* RFC3489bis-11 */
  STUN_BAD_REQUEST=400,      /* RFC3489bis-11 */
  STUN_UNAUTHORIZED=401,      /* RFC3489bis-11 */
  STUN_UNKNOWN_ATTRIBUTE=420,    /* RFC3489bis-11 */
  STUN_NO_BINDING=437,      /* TURN-04 */
  STUN_STALE_NONCE=438,      /* RFC3489bis-11 */
  STUN_ACT_DST_ALREADY=439,    /* TURN-04 */
  STUN_UNSUPP_FAMILY=440,      /* TURN-IPv6-03 */
  STUN_UNSUPP_TRANSPORT=442,    /* TURN-04 */
  STUN_INVALID_IP=443,      /* TURN-04 */
  STUN_INVALID_PORT=444,      /* TURN-04 */
  STUN_OP_TCP_ONLY=445,      /* TURN-04 */
  STUN_CONN_ALREADY=446,      /* TURN-04 */
  STUN_ALLOC_OVER_QUOTA=486,    /* TURN-04 */
  STUN_ROLE_CONFLICT=487,      /* ICE-18 */
  STUN_SERVER_ERROR=500,      /* RFC3489bis-11 */
  STUN_SERVER_CAPACITY=507,    /* TURN-04 */
  STUN_ERROR_MAX=699
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

bool stun_has_cookie (const uint8_t *msg);


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

/**
 * Computes the FINGERPRINT checksum of a STUN message.
 * @param msg pointer to the STUN message
 * @param len size of the message from header (inclusive) and up to
 *            FINGERPRINT attribute (inclusive)
 *
 * @return fingerprint value in <b>host</b> byte order.
 */
uint32_t stun_fingerprint (const uint8_t *msg, size_t len);

/**
 * Computes the MESSAGE-INTEGRITY hash of a STUN message.
 * @param msg pointer to the STUN message
 * @param len size of the message from header (inclusive) and up to
 *            MESSAGE-INTEGRITY attribute (inclusive)
 * @param sha output buffer for SHA1 hash (20 bytes)
 * @param key HMAC key
 * @param keylen HMAC key bytes length
 *
 * @return fingerprint value in <b>host</b> byte order.
 */
void stun_sha1 (const uint8_t *msg, size_t len,
                uint8_t *sha, const void *key, size_t keylen);

/**
 * SIP H(A1) computation
 */
void stun_hash_creds (const char *realm, const char *login, const char *pw,
                      unsigned char md5[16]);

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
 * Looks for an attribute in a *valid* STUN message.
 * @param msg message buffer
 * @param type STUN attribute type (host byte order)
 * @param palen [OUT] pointer to store the byte length of the attribute
 * @return a pointer to the start of the attribute payload if found,
 * otherwise NULL.
 */
const void *
stun_find (const uint8_t *restrict msg, stun_attr_type_t type,
           uint16_t *restrict palen);

/**
 * Checks if an attribute is present within a STUN message.
 *
 * @param msg valid STUN message
 * @param type STUN attribute type (host byte order)
 *
 * @return whether there is a MESSAGE-INTEGRITY attribute
 */
static inline bool stun_present (const uint8_t *msg, stun_attr_type_t type)
{
  uint16_t dummy;
  return stun_find (msg, type, &dummy) != NULL;
}


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
 *
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload was not 32-bits.
 * In case of error, @a *pval is not modified.
 */
int stun_find32 (const uint8_t *msg, stun_attr_type_t type, uint32_t *pval);

/**
 * Extracts a 64-bits attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param pval [OUT] where to store the host byte ordered value
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload was not 64-bits.
 * In case of error, @a *pval is not modified.
 */
int stun_find64 (const uint8_t *msg, stun_attr_type_t type, uint64_t *pval);

/**
 * Extracts an UTF-8 string from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param buf buffer to store the extracted string
 * @param maxcp maximum number of code points allowed
 *  (@a buf should be (6*maxcp+1) bytes long)
 *
 * @return 0 on success, ENOENT if attribute not found, EINVAL if attribute
 * improperly encoded, ENOBUFS if the buffer size was too small.
 *
 * @note A nul-byte is appended at the end.
 */
int stun_find_string (const uint8_t *restrict msg, stun_attr_type_t type,
                      char *buf, size_t buflen);

# define STUN_MAX_STR (763u)
# define STUN_MAX_CP  (127u)

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
void stun_init_response (uint8_t *ans, size_t msize, const uint8_t *req);

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


void *stun_append (uint8_t *msg, size_t msize, stun_attr_type_t type,
                   size_t length);
int stun_append_bytes (uint8_t *restrict msg, size_t msize,
                       stun_attr_type_t type, const void *data, size_t len);

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


# ifndef NDEBUG
/**
 * This function is for debugging only, which is why it is only defined under
 * !NDEBUG. It should really only be used in run-time assertions, as it cannot
 * detect all possible errors. stun_validate() should be used instead in real
 * code.
 *
 * @param msg pointer to a potential STUN message
 * @return whether the pointer refers to a valid STUN message
 */
static inline bool stun_valid (const uint8_t *msg)
{
  size_t length = 20u + stun_length (msg);
  return stun_validate (msg, length) == (ssize_t)length;
}
# endif

#endif
