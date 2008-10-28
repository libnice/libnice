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

#ifndef _STUN_MESSAGE_H
#define _STUN_MESSAGE_H


#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include "constants.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

typedef struct stun_message_t StunMessage;

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
  STUN_ALLOCATE=0x003,    /* TURN-09 */
  STUN_SET_ACTIVE_DST=0x004,  /* TURN-04 */
  STUN_REFRESH=0x004,  /* TURN-09 */
  STUN_SEND=0x004,  /* TURN-09 */
  STUN_CONNECT=0x005,    /* TURN-04 */
  STUN_OLD_SET_ACTIVE_DST=0x006,  /* TURN-00 */
  STUN_IND_SEND=0x006,    /* TURN-04 */
  STUN_IND_DATA=0x007,    /* TURN-04 */
  STUN_IND_CONNECT_STATUS=0x008,  /* TURN-04 */
  STUN_CHANNELBIND= 0x009 /* TURN-09 */
} stun_method_t;

/**
 * STUN attribute types
 * Should be in sync with stun_is_unknown()
 */
typedef enum
{
  /* Mandatory attributes */
  /* 0x0000 */        /* reserved */
  STUN_ATTRIBUTE_MAPPED_ADDRESS=0x0001,    /* RFC3489bis-11 */
  STUN_ATTRIBUTE_OLD_RESPONSE_ADDRESS=0x0002,  /* old RFC3489 */
  STUN_ATTRIBUTE_OLD_CHANGE_REQUEST=0x0003,    /* old RFC3489 */
  STUN_ATTRIBUTE_OLD_SOURCE_ADDRESS=0x0004,    /* old RFC3489 */
  STUN_ATTRIBUTE_OLD_CHANGED_ADDRESS=0x0005,  /* old RFC3489 */
  STUN_ATTRIBUTE_USERNAME=0x0006,      /* RFC3489bis-11 */
  STUN_ATTRIBUTE_OLD_PASSWORD=0x0007,    /* old RFC3489 */
  STUN_ATTRIBUTE_MESSAGE_INTEGRITY=0x0008,    /* RFC3489bis-11 */
  STUN_ATTRIBUTE_ERROR_CODE=0x0009,      /* RFC3489bis-11 */
  STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES=0x000A,    /* RFC3489bis-11 */
  STUN_ATTRIBUTE_OLD_REFLECTED_FROM=0x000B,    /* old RFC3489 */
  STUN_ATTRIBUTE_CHANNEL_NUMBER=0x000C,        /* TURN-09 */
  STUN_ATTRIBUTE_LIFETIME=0x000D,      /* TURN-04 */
  /* 0x000E */        /* reserved */
  STUN_ATTRIBUTE_MAGIC_COOKIE=0x000F,        /* STUN/TURN magic cookie */
  STUN_ATTRIBUTE_BANDWIDTH=0x0010,      /* TURN-04 */
  STUN_ATTRIBUTE_DESTINATION_ADDRESS=0x0011,        /* TURN jingle */
  STUN_ATTRIBUTE_REMOTE_ADDRESS=0x0012,    /* TURN-04 */
  STUN_ATTRIBUTE_PEER_ADDRESS=0x0012,    /* TURN-09 */
  STUN_ATTRIBUTE_DATA=0x0013,      /* TURN-04 */
  STUN_ATTRIBUTE_REALM=0x0014,      /* RFC3489bis-11 */
  STUN_ATTRIBUTE_NONCE=0x0015,      /* RFC3489bis-11 */
  STUN_ATTRIBUTE_RELAY_ADDRESS=0x0016,    /* TURN-04 */
  STUN_ATTRIBUTE_RELAYED_ADDRESS=0x0016,    /* TURN-09 */
  STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE=0x0017,  /* TURN-IPv6-03 */
  STUN_ATTRIBUTE_REQUESTED_PORT_PROPS=0x0018,  /* TURN-04 */
  STUN_ATTRIBUTE_REQUESTED_TRANSPORT=0x0019,  /* TURN-04 */
  /* 0x001A */        /* reserved */
  /* 0x001B */        /* reserved */
  /* 0x001C */        /* reserved */
  /* 0x001D */        /* reserved */
  /* 0x001E */        /* reserved */
  /* 0x001F */        /* reserved */
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS=0x0020,    /* RFC3489bis-11 */
  STUN_ATTRIBUTE_TIMER_VAL=0x0021,      /* TURN-04 */
  STUN_ATTRIBUTE_REQUESTED_IP=0x0022,    /* TURN-04 */
  STUN_ATTRIBUTE_RESERVATION_TOKEN=0x0022,    /* TURN-09 */
  STUN_ATTRIBUTE_CONNECT_STAT=0x0023,    /* TURN-04 */
  STUN_ATTRIBUTE_PRIORITY=0x0024,      /* ICE-18 */
  STUN_ATTRIBUTE_USE_CANDIDATE=0x0025,    /* ICE-18 */
  /* 0x0026 */        /* reserved */
  /* 0x0027 */        /* reserved */
  /* 0x0028 */        /* reserved */
  STUN_ATTRIBUTE_XOR_INTERNAL_ADDRESS=0x0029, /* wing-nat-control-04 */
  /* 0x002A-0x7fff */      /* reserved */

  /* Optional attributes */
  /* 0x8000-0x8021 */      /* reserved */
  STUN_ATTRIBUTE_OPTIONS=0x8001, /* libjingle */
  STUN_ATTRIBUTE_SOFTWARE=0x8022,      /* RFC3489bis-17 */
  STUN_ATTRIBUTE_ALTERNATE_SERVER=0x8023,    /* RFC3489bis-11 */
  STUN_ATTRIBUTE_REFRESH_INTERVAL=0x8024,    /* wing-nat-control-04 */
  /* 0x8025 */        /* reserved */
  /* 0x8026 */        /* reserved */
  /* 0x8027 */        /* reserved */
  STUN_ATTRIBUTE_FINGERPRINT=0x8028,    /* RFC3489bis-11 */
  STUN_ATTRIBUTE_ICE_CONTROLLED=0x8029,    /* ICE-18 */
  STUN_ATTRIBUTE_ICE_CONTROLLING=0x802A,    /* ICE-18 */
  /* 0x802B-0xFFFF */      /* reserved */
} stun_attr_type_t;


static const uint16_t STUN_ALL_KNOWN_ATTRIBUTES[] =
  {
    STUN_ATTRIBUTE_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_OLD_RESPONSE_ADDRESS,
    STUN_ATTRIBUTE_OLD_CHANGE_REQUEST,
    STUN_ATTRIBUTE_OLD_SOURCE_ADDRESS,
    STUN_ATTRIBUTE_OLD_CHANGED_ADDRESS,
    STUN_ATTRIBUTE_USERNAME,
    STUN_ATTRIBUTE_OLD_PASSWORD,
    STUN_ATTRIBUTE_MESSAGE_INTEGRITY,
    STUN_ATTRIBUTE_ERROR_CODE,
    STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
    STUN_ATTRIBUTE_OLD_REFLECTED_FROM,
    STUN_ATTRIBUTE_CHANNEL_NUMBER,
    STUN_ATTRIBUTE_LIFETIME,
    STUN_ATTRIBUTE_MAGIC_COOKIE,
    STUN_ATTRIBUTE_BANDWIDTH,
    STUN_ATTRIBUTE_DESTINATION_ADDRESS,
    STUN_ATTRIBUTE_REMOTE_ADDRESS,
    STUN_ATTRIBUTE_PEER_ADDRESS,
    STUN_ATTRIBUTE_DATA,
    STUN_ATTRIBUTE_REALM,
    STUN_ATTRIBUTE_NONCE,
    STUN_ATTRIBUTE_RELAY_ADDRESS,
    STUN_ATTRIBUTE_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE,
    STUN_ATTRIBUTE_REQUESTED_PORT_PROPS,
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT,
    STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_TIMER_VAL,
    STUN_ATTRIBUTE_REQUESTED_IP,
    STUN_ATTRIBUTE_RESERVATION_TOKEN,
    STUN_ATTRIBUTE_CONNECT_STAT,
    STUN_ATTRIBUTE_PRIORITY,
    STUN_ATTRIBUTE_USE_CANDIDATE,
    STUN_ATTRIBUTE_XOR_INTERNAL_ADDRESS,
    0
  };

typedef uint8_t stun_transid_t[STUN_MESSAGE_TRANS_ID_LEN];


/**
 * STUN error codes
 * Should be in sync with stun_strerror()
 */
typedef enum
{
  STUN_ERROR_TRY_ALTERNATE=300,      /* RFC3489bis-11 */
  STUN_ERROR_BAD_REQUEST=400,      /* RFC3489bis-11 */
  STUN_ERROR_UNAUTHORIZED=401,      /* RFC3489bis-11 */
  STUN_ERROR_UNKNOWN_ATTRIBUTE=420,    /* RFC3489bis-11 */
  STUN_ERROR_NO_BINDING=437,      /* TURN-04 */
  STUN_ERROR_STALE_NONCE=438,      /* RFC3489bis-11 */
  STUN_ERROR_ACT_DST_ALREADY=439,    /* TURN-04 */
  STUN_ERROR_UNSUPP_FAMILY=440,      /* TURN-IPv6-03 */
  STUN_ERROR_UNSUPP_TRANSPORT=442,    /* TURN-04 */
  STUN_ERROR_INVALID_IP=443,      /* TURN-04 */
  STUN_ERROR_INVALID_PORT=444,      /* TURN-04 */
  STUN_ERROR_OP_TCP_ONLY=445,      /* TURN-04 */
  STUN_ERROR_CONN_ALREADY=446,      /* TURN-04 */
  STUN_ERROR_ALLOC_OVER_QUOTA=486,    /* TURN-04 */
  STUN_ERROR_ROLE_CONFLICT=487,      /* ICE-18 */
  STUN_ERROR_SERVER_ERROR=500,      /* RFC3489bis-11 */
  STUN_ERROR_SERVER_CAPACITY=507,    /* TURN-04 */
  STUN_ERROR_MAX=699
} stun_error_t;


#include "stunagent.h"
#include "stunhmac.h"
#include "stuncrc32.h"
#include "utils.h"
#include "stun3489bis.h"

struct stun_message_t {
  StunAgent *agent;
  uint8_t *buffer;
  size_t buffer_len;
  uint8_t *key;
  size_t key_len;
  uint8_t long_term_key[16];
  bool long_term_valid;
};

/**
 * Initializes a STUN message buffer, with no attributes.
 * @param c STUN message class (host byte order)
 * @param m STUN message method (host byte order)
 * @param id 16-bytes transaction ID
 * @return TRUE if the initialization was successful
 */
bool stun_message_init (StunMessage *msg, stun_class_t c, stun_method_t m,
    const stun_transid_t id);

/**
 * Returns the length of the stun message
 * @param msg the STUN message
 */
uint16_t stun_message_length (const StunMessage *msg);

/**
 * Looks for an attribute in a *valid* STUN message.
 * @param msg message buffer
 * @param type STUN attribute type (host byte order)
 * @param palen [OUT] pointer to store the byte length of the attribute
 * @return a pointer to the start of the attribute payload if found,
 * otherwise NULL.
 */
const void * stun_message_find (const StunMessage * msg, stun_attr_type_t type,
    uint16_t *restrict palen);


/**
 * Looks for a flag attribute within a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @return 0 if flag is present, ENOENT if it is not, EINVAL if flag payload
 * size is not zero.
 */
int stun_message_find_flag (const StunMessage *msg, stun_attr_type_t type);

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
int stun_message_find32 (const StunMessage *msg, stun_attr_type_t type,
    uint32_t *pval);

/**
 * Extracts a 64-bits attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param pval [OUT] where to store the host byte ordered value
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload was not 64-bits.
 * In case of error, @a *pval is not modified.
 */
int stun_message_find64 (const StunMessage *msg, stun_attr_type_t type,
    uint64_t *pval);

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
int stun_message_find_string (const StunMessage *msg, stun_attr_type_t type,
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
int stun_message_find_addr (const StunMessage *msg, stun_attr_type_t type,
    struct sockaddr *restrict addr, socklen_t *restrict addrlen);

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
int stun_message_find_xor_addr (const StunMessage *msg, stun_attr_type_t type,
    struct sockaddr *restrict addr, socklen_t *restrict addrlen);

int stun_message_find_xor_addr_full (const StunMessage *msg,
    stun_attr_type_t type, struct sockaddr *restrict addr,
    socklen_t *restrict addrlen, uint32_t magic_cookie);


int stun_message_find_error (const StunMessage *msg, int *restrict code);

void *stun_message_append (StunMessage *msg, stun_attr_type_t type,
    size_t length);

int stun_message_append_bytes (StunMessage *msg, stun_attr_type_t type,
    const void *data, size_t len);

/**
 * Appends an empty ("flag") attribute to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
int stun_message_append_flag (StunMessage *msg, stun_attr_type_t type);

/**
 * Appends an attribute consisting of a 32-bits value to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param value payload (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
int stun_message_append32 (StunMessage *msg, stun_attr_type_t type,
    uint32_t value);

/**
 * Appends an attribute consisting of a 64-bits value to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param value payload (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
int stun_message_append64 (StunMessage *msg, stun_attr_type_t type,
    uint64_t value);

/**
 * Appends an attribute from a nul-terminated string.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param str nul-terminated string
 * @return 0 on success, ENOBUFS on error.
 */
int stun_message_append_string (StunMessage *msg, stun_attr_type_t type,
    const char *str);

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
int stun_message_append_addr (StunMessage * msg, stun_attr_type_t type,
    const struct sockaddr *restrict addr, socklen_t addrlen);

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
int stun_message_append_xor_addr (StunMessage * msg, stun_attr_type_t type,
    const struct sockaddr *restrict addr, socklen_t addrlen);

int stun_message_append_xor_addr_full (StunMessage * msg, stun_attr_type_t type,
    const struct sockaddr *restrict addr, socklen_t addrlen,
    uint32_t magic_cookie);

/**
 * Appends an ERROR-CODE attribute.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param code STUN host-byte order integer error code
 * @return 0 on success, or ENOBUFS otherwise
 */
int stun_message_append_error (StunMessage * msg, stun_error_t code);

#define STUN_MESSAGE_BUFFER_INCOMPLETE 0
#define STUN_MESSAGE_BUFFER_INVALID -1


int stun_message_validate_buffer_length (const uint8_t *msg, size_t length);

void stun_message_id (const StunMessage *msg, stun_transid_t id);

stun_class_t stun_message_get_class (const StunMessage *msg);
stun_method_t stun_message_get_method (const StunMessage *msg);
bool stun_message_has_attribute (const StunMessage *msg, stun_attr_type_t type);

#endif /* _STUN_MESSAGE_H */
