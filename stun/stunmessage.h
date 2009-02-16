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


#ifdef _WIN32
#include "win32_common.h"
#else
#include <stdint.h>
#include <stdbool.h>
#endif

#include <sys/types.h>
#include "constants.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

typedef struct stun_message_t StunMessage;

/**
 * StunClass:
 * @STUN_REQUEST: A STUN Request message
 * @STUN_INDICATION: A STUN indication message
 * @STUN_RESPONSE: A STUN Response message
 * @STUN_ERROR: A STUN Error message
 *
 * This enum is used to represent the class of
 * a STUN message, as defined in RFC5389
 */

/* Message classes */
typedef enum
{
  STUN_REQUEST=0,
  STUN_INDICATION=1,
  STUN_RESPONSE=2,
  STUN_ERROR=3
} StunClass;


/**
 * StunMethod:
 * @STUN_BINDING: The Binding method as defined by the RFC5389
 * @STUN_SHARED_SECRET: The Shared-Secret method as defined by the RFC3489
 * @STUN_ALLOCATE: The Allocate method as defined by the TURN draft 12
 * @STUN_SET_ACTIVE_DST: The Set-Active-Destination method as defined by
 * the TURN draft 4
 * @STUN_REFRESH: The Refresh method as defined by the TURN draft 12
 * @STUN_SEND: The Send method as defined by the TURN draft 00
 * @STUN_CONNECT: The Connect method as defined by the TURN draft 4
 * @STUN_OLD_SET_ACTIVE_DST: The older Set-Active-Destination method as
 * defined by the TURN draft 0
 * @STUN_IND_SEND: The Send method used in indication messages as defined
 * by the TURN draft 12
 * @STUN_IND_DATA: The Data method used in indication messages as defined
 * by the TURN draft 12
 * @STUN_IND_CONNECT_STATUS:  The Connect-Status method used in indication
 * messages as defined by the TURN draft 4
 * @STUN_CREATEPERMISSION: The CreatePermission method as defined by
 * the TURN draft 12
 * @STUN_CHANNELBIND: The ChannelBind method as defined by the TURN draft 12
 *
 * This enum is used to represent the method of
 * a STUN message, as defined by various RFCs
 */
/* Message methods */
typedef enum
{
  STUN_BINDING=0x001,    /* RFC5389 */
  STUN_SHARED_SECRET=0x002,  /* old RFC3489 */
  STUN_ALLOCATE=0x003,    /* TURN-12 */
  STUN_SET_ACTIVE_DST=0x004,  /* TURN-04 */
  STUN_REFRESH=0x004,  /* TURN-12 */
  STUN_SEND=0x004,  /* TURN-00 */
  STUN_CONNECT=0x005,    /* TURN-04 */
  STUN_OLD_SET_ACTIVE_DST=0x006,  /* TURN-00 */
  STUN_IND_SEND=0x006,    /* TURN-12 */
  STUN_IND_DATA=0x007,    /* TURN-12 */
  STUN_IND_CONNECT_STATUS=0x008,  /* TURN-04 */
  STUN_CREATEPERMISSION= 0x008, /* TURN-12 */
  STUN_CHANNELBIND= 0x009 /* TURN-12 */
} StunMethod;

/**
 * StunAttribute:
 * @STUN_ATTRIBUTE_MAPPED_ADDRESS: The MAPPED-ADDRESS attribute as defined
 * by RFC5389
 * @STUN_ATTRIBUTE_RESPONSE_ADDRESS: The RESPONSE-ADDRESS attribute as defined
 * by RFC3489
 * @STUN_ATTRIBUTE_CHANGE_REQUEST: The CHANGE-REQUEST attribute as defined by
 * RFC3489
 * @STUN_ATTRIBUTE_SOURCE_ADDRESS: The SOURCE-ADDRESS attribute as defined by
 * RFC3489
 * @STUN_ATTRIBUTE_CHANGED_ADDRESS: The CHANGED-ADDRESS attribute as defined
 * by RFC3489
 * @STUN_ATTRIBUTE_USERNAME: The USERNAME attribute as defined by RFC5389
 * @STUN_ATTRIBUTE_PASSWORD: The PASSWORD attribute as defined by RFC3489
 * @STUN_ATTRIBUTE_MESSAGE_INTEGRITY: The MESSAGE-INTEGRITY attribute as defined
 * by RFC5389
 * @STUN_ATTRIBUTE_ERROR_CODE: The ERROR-CODE attribute as defined by RFC5389
 * @STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES: The UNKNOWN-ATTRIBUTES attribute as
 * defined by RFC5389
 * @STUN_ATTRIBUTE_REFLECTED_FROM: The REFLECTED-FROM attribute as defined
 * by RFC3489
 * @STUN_ATTRIBUTE_CHANNEL_NUMBER: The CHANNEL-NUMBER attribute as defined by
 * TURN draft 09 and 12
 * @STUN_ATTRIBUTE_LIFETIME: The LIFETIME attribute as defined by TURN
 * draft 04, 09 and 12
 * @STUN_ATTRIBUTE_MAGIC_COOKIE: The MAGIC-COOKIE attribute as defined by
 * the rosenberg-midcom TURN draft 08
 * @STUN_ATTRIBUTE_BANDWIDTH: The BANDWIDTH attribute as defined by TURN draft 04
 * @STUN_ATTRIBUTE_DESTINATION_ADDRESS: The DESTINATION-ADDRESS attribute as
 * defined by the rosenberg-midcom TURN draft 08
 * @STUN_ATTRIBUTE_REMOTE_ADDRESS: The REMOTE-ADDRESS attribute as defined by
 * TURN draft 04
 * @STUN_ATTRIBUTE_PEER_ADDRESS: The PEER-ADDRESS attribute as defined by
 * TURN draft 09
 * @STUN_ATTRIBUTE_XOR_PEER_ADDRESS: The XOR-PEER-ADDRESS attribute as defined
 * by TURN draft 12
 * @STUN_ATTRIBUTE_DATA: The DATA attribute as defined by TURN draft 04,
 * 09 and 12
 * @STUN_ATTRIBUTE_REALM: The REALM attribute as defined by RFC5389
 * @STUN_ATTRIBUTE_NONCE: The NONCE attribute as defined by RFC5389
 * @STUN_ATTRIBUTE_RELAY_ADDRESS: The RELAY-ADDRESS attribute as defined by
 * TURN draft 04
 * @STUN_ATTRIBUTE_RELAYED_ADDRESS: The RELAYED-ADDRESS attribute as defined by
 * TURN draft 09
 * @STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS: The XOR-RELAYED-ADDRESS attribute as
 * defined by TURN draft 12
 * @STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE: The REQUESTED-ADDRESS-TYPE attribute
 * as defined by TURN-IPV6 draft 05
 * @STUN_ATTRIBUTE_REQUESTED_PORT_PROPS: The REQUESTED-PORT-PROPS attribute
 * as defined by TURN draft 04
 * @STUN_ATTRIBUTE_REQUESTED_PROPS: The REQUESTED-PROPS attribute as defined
 * by TURN draft 09
 * @STUN_ATTRIBUTE_EVEN_PORT: The EVEN-PORT attribute as defined by TURN draft 12
 * @STUN_ATTRIBUTE_REQUESTED_TRANSPORT: The REQUESTED-TRANSPORT attribute as
 * defined by TURN draft 12
 * @STUN_ATTRIBUTE_DONT_FRAGMENT: The DONT-FRAGMENT attribute as defined
 * by TURN draft 12
 * @STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS: The XOR-MAPPED-ADDRESS attribute as
 * defined by RFC5389
 * @STUN_ATTRIBUTE_TIMER_VAL: The TIMER-VAL attribute as defined by TURN draft 04
 * @STUN_ATTRIBUTE_REQUESTED_IP: The REQUESTED-IP attribute as defined by
 * TURN draft 04
 * @STUN_ATTRIBUTE_RESERVATION_TOKEN: The RESERVATION-TOKEN attribute as defined
 * by TURN draft 09 and 12
 * @STUN_ATTRIBUTE_CONNECT_STAT: The CONNECT-STAT attribute as defined by TURN
 * draft 04
 * @STUN_ATTRIBUTE_PRIORITY: The PRIORITY attribute as defined by ICE draft 19
 * @STUN_ATTRIBUTE_USE_CANDIDATE: The USE-CANDIDATE attribute as defined by
 * ICE draft 19
 * @STUN_ATTRIBUTE_OPTIONS: The OPTIONS optional attribute as defined by
 * libjingle
 * @STUN_ATTRIBUTE_SOFTWARE: The SOFTWARE optional attribute as defined by RFC5389
 * @STUN_ATTRIBUTE_ALTERNATE_SERVER: The ALTERNATE-SERVER optional attribute as
 * defined by RFC5389
 * @STUN_ATTRIBUTE_FINGERPRINT: The FINGERPRINT optional attribute as defined
 * by RFC5389
 * @STUN_ATTRIBUTE_ICE_CONTROLLED: The ICE-CONTROLLED optional attribute as
 * defined by ICE draft 19
 * @STUN_ATTRIBUTE_ICE_CONTROLLING: The ICE-CONTROLLING optional attribute as
 * defined by ICE draft 19
 *
 * Known STUN attribute types as defined by various RFCs and drafts
 */
/* Should be in sync with stun_is_unknown() */
typedef enum
{
  /* Mandatory attributes */
  /* 0x0000 */        /* reserved */
  STUN_ATTRIBUTE_MAPPED_ADDRESS=0x0001,    /* RFC5389 */
  STUN_ATTRIBUTE_RESPONSE_ADDRESS=0x0002,  /* old RFC3489 */
  STUN_ATTRIBUTE_CHANGE_REQUEST=0x0003,    /* old RFC3489 */
  STUN_ATTRIBUTE_SOURCE_ADDRESS=0x0004,    /* old RFC3489 */
  STUN_ATTRIBUTE_CHANGED_ADDRESS=0x0005,  /* old RFC3489 */
  STUN_ATTRIBUTE_USERNAME=0x0006,      /* RFC5389 */
  STUN_ATTRIBUTE_PASSWORD=0x0007,    /* old RFC3489 */
  STUN_ATTRIBUTE_MESSAGE_INTEGRITY=0x0008,    /* RFC5389 */
  STUN_ATTRIBUTE_ERROR_CODE=0x0009,      /* RFC5389 */
  STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES=0x000A,    /* RFC5389 */
  STUN_ATTRIBUTE_REFLECTED_FROM=0x000B,    /* old RFC3489 */
  STUN_ATTRIBUTE_CHANNEL_NUMBER=0x000C,        /* TURN-12 */
  STUN_ATTRIBUTE_LIFETIME=0x000D,      /* TURN-12 */
  /* 0x000E */        /* reserved (was ALTERNATE-SERVER from midcom-TURN 08 */
  STUN_ATTRIBUTE_MAGIC_COOKIE=0x000F,        /* midcom-TURN 08 */
  STUN_ATTRIBUTE_BANDWIDTH=0x0010,      /* TURN-04 */
  STUN_ATTRIBUTE_DESTINATION_ADDRESS=0x0011,        /* midcom-TURN 08 */
  STUN_ATTRIBUTE_REMOTE_ADDRESS=0x0012,    /* TURN-04 */
  STUN_ATTRIBUTE_PEER_ADDRESS=0x0012,    /* TURN-09 */
  STUN_ATTRIBUTE_XOR_PEER_ADDRESS=0x0012,    /* TURN-12 */
  STUN_ATTRIBUTE_DATA=0x0013,      /* TURN-12 */
  STUN_ATTRIBUTE_REALM=0x0014,      /* RFC5389 */
  STUN_ATTRIBUTE_NONCE=0x0015,      /* RFC5389 */
  STUN_ATTRIBUTE_RELAY_ADDRESS=0x0016,    /* TURN-04 */
  STUN_ATTRIBUTE_RELAYED_ADDRESS=0x0016,    /* TURN-09 */
  STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS=0x0016,    /* TURN-12 */
  STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE=0x0017,  /* TURN-IPv6-05 */
  STUN_ATTRIBUTE_REQUESTED_PORT_PROPS=0x0018,  /* TURN-04 */
  STUN_ATTRIBUTE_REQUESTED_PROPS=0x0018,  /* TURN-09 */
  STUN_ATTRIBUTE_EVEN_PORT=0x0018,  /* TURN-12 */
  STUN_ATTRIBUTE_REQUESTED_TRANSPORT=0x0019,  /* TURN-12 */
  STUN_ATTRIBUTE_DONT_FRAGMENT=0x001A,  /* TURN-12 */
  /* 0x001B */        /* reserved */
  /* 0x001C */        /* reserved */
  /* 0x001D */        /* reserved */
  /* 0x001E */        /* reserved */
  /* 0x001F */        /* reserved */
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS=0x0020,    /* RFC5389 */
  STUN_ATTRIBUTE_TIMER_VAL=0x0021,      /* TURN-04 */
  STUN_ATTRIBUTE_REQUESTED_IP=0x0022,    /* TURN-04 */
  STUN_ATTRIBUTE_RESERVATION_TOKEN=0x0022,    /* TURN-09 */
  STUN_ATTRIBUTE_CONNECT_STAT=0x0023,    /* TURN-04 */
  STUN_ATTRIBUTE_PRIORITY=0x0024,      /* ICE-19 */
  STUN_ATTRIBUTE_USE_CANDIDATE=0x0025,    /* ICE-19 */
  /* 0x0026 */        /* reserved */
  /* 0x0027 */        /* reserved */
  /* 0x0028 */        /* reserved */
  /* 0x0029 */        /* reserved */
  /* 0x002A-0x7fff */      /* reserved */

  /* Optional attributes */
  /* 0x8000-0x8021 */      /* reserved */
  STUN_ATTRIBUTE_OPTIONS=0x8001, /* libjingle */
  STUN_ATTRIBUTE_SOFTWARE=0x8022,      /* RFC5389 */
  STUN_ATTRIBUTE_ALTERNATE_SERVER=0x8023,    /* RFC5389 */
  /* 0x8024 */        /* reserved */
  /* 0x8025 */        /* reserved */
  /* 0x8026 */        /* reserved */
  /* 0x8027 */        /* reserved */
  STUN_ATTRIBUTE_FINGERPRINT=0x8028,    /* RFC5389 */
  STUN_ATTRIBUTE_ICE_CONTROLLED=0x8029,    /* ICE-19 */
  STUN_ATTRIBUTE_ICE_CONTROLLING=0x802A,    /* ICE-19 */
  /* 0x802B-0xFFFF */      /* reserved */
} StunAttribute;


/**
 * STUN_ALL_KNOWN_ATTRIBUTES:
 *
 * An array containing all the currently known and defined mandatory attributes
 * from StunAttribute
 */
/* Should be in sync with StunAttribute */
static const uint16_t STUN_ALL_KNOWN_ATTRIBUTES[] =
  {
    STUN_ATTRIBUTE_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_RESPONSE_ADDRESS,
    STUN_ATTRIBUTE_CHANGE_REQUEST,
    STUN_ATTRIBUTE_SOURCE_ADDRESS,
    STUN_ATTRIBUTE_CHANGED_ADDRESS,
    STUN_ATTRIBUTE_USERNAME,
    STUN_ATTRIBUTE_PASSWORD,
    STUN_ATTRIBUTE_MESSAGE_INTEGRITY,
    STUN_ATTRIBUTE_ERROR_CODE,
    STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
    STUN_ATTRIBUTE_REFLECTED_FROM,
    STUN_ATTRIBUTE_CHANNEL_NUMBER,
    STUN_ATTRIBUTE_LIFETIME,
    STUN_ATTRIBUTE_MAGIC_COOKIE,
    STUN_ATTRIBUTE_BANDWIDTH,
    STUN_ATTRIBUTE_DESTINATION_ADDRESS,
    STUN_ATTRIBUTE_REMOTE_ADDRESS,
    STUN_ATTRIBUTE_PEER_ADDRESS,
    STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
    STUN_ATTRIBUTE_DATA,
    STUN_ATTRIBUTE_REALM,
    STUN_ATTRIBUTE_NONCE,
    STUN_ATTRIBUTE_RELAY_ADDRESS,
    STUN_ATTRIBUTE_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE,
    STUN_ATTRIBUTE_REQUESTED_PORT_PROPS,
    STUN_ATTRIBUTE_REQUESTED_PROPS,
    STUN_ATTRIBUTE_EVEN_PORT,
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT,
    STUN_ATTRIBUTE_DONT_FRAGMENT,
    STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_TIMER_VAL,
    STUN_ATTRIBUTE_REQUESTED_IP,
    STUN_ATTRIBUTE_RESERVATION_TOKEN,
    STUN_ATTRIBUTE_CONNECT_STAT,
    STUN_ATTRIBUTE_PRIORITY,
    STUN_ATTRIBUTE_USE_CANDIDATE,
    0
  };

/**
 * StunTransactionId:
 *
 * A type that holds a STUN transaction id.
 */
typedef uint8_t StunTransactionId[STUN_MESSAGE_TRANS_ID_LEN];


/**
 * StunError:
 * @STUN_ERROR_TRY_ALTERNATE: The ERROR-CODE value for the
 * "Try Alternate" error as defined in RFC5389
 * @STUN_ERROR_BAD_REQUEST: The ERROR-CODE value for the
 * "Bad Request" error as defined in RFC5389
 * @STUN_ERROR_UNAUTHORIZED: The ERROR-CODE value for the
 * "Unauthorized" error as defined in RFC5389
 * @STUN_ERROR_UNKNOWN_ATTRIBUTE: The ERROR-CODE value for the
 * "Unknown Attribute" error as defined in RFC5389
 * @STUN_ERROR_ALLOCATION_MISMATCH:The ERROR-CODE value for the
 * "Allocation Mismatch" error as defined in TURN draft 12.
 * Equivalent to the "No Binding" error defined in TURN draft 04.
 * @STUN_ERROR_STALE_NONCE: The ERROR-CODE value for the
 * "Stale Nonce" error as defined in RFC5389
 * @STUN_ERROR_ACT_DST_ALREADY: The ERROR-CODE value for the
 * "Active Destination Already Set" error as defined in TURN draft 04.
 * @STUN_ERROR_UNSUPPORTED_FAMILY: The ERROR-CODE value for the
 * "Address Family not Supported" error as defined in TURN IPV6 Draft 05.
 * @STUN_ERROR_UNSUPPORTED_TRANSPORT:he ERROR-CODE value for the
 * "Unsupported Transport Protocol" error as defined in TURN Draft 12.
 * @STUN_ERROR_INVALID_IP: The ERROR-CODE value for the
 * "Invalid IP Address" error as defined in TURN draft 04.
 * @STUN_ERROR_INVALID_PORT: The ERROR-CODE value for the
 * "Invalid Port" error as defined in TURN draft 04.
 * @STUN_ERROR_OP_TCP_ONLY: The ERROR-CODE value for the
 * "Operation for TCP Only" error as defined in TURN draft 04.
 * @STUN_ERROR_CONN_ALREADY: The ERROR-CODE value for the
 * "Connection Already Exists" error as defined in TURN draft 04.
 * @STUN_ERROR_ALLOCATION_QUOTA_REACHED: The ERROR-CODE value for the
 * "Allocation Quota Reached" error as defined in TURN draft 12.
 * @STUN_ERROR_ROLE_CONFLICT:The ERROR-CODE value for the
 * "Role Conflict" error as defined in ICE draft 19.
 * @STUN_ERROR_SERVER_ERROR: The ERROR-CODE value for the
 * "Server Error" error as defined in RFC5389
 * @STUN_ERROR_SERVER_CAPACITY: The ERROR-CODE value for the
 * "Insufficient Capacity" error as defined in TURN draft 04.
 * @STUN_ERROR_INSUFFICIENT_CAPACITY: The ERROR-CODE value for the
 * "Insufficient Capacity" error as defined in TURN draft 12.
 * @STUN_ERROR_MAX: The maximum possible ERROR-CODE value as defined by RFC 5389.
 *
 * STUN error codes as defined by various RFCs and drafts
 */
/* Should be in sync with stun_strerror() */
typedef enum
{
  STUN_ERROR_TRY_ALTERNATE=300,      /* RFC5389 */
  STUN_ERROR_BAD_REQUEST=400,      /* RFC5389 */
  STUN_ERROR_UNAUTHORIZED=401,      /* RFC5389 */
  STUN_ERROR_UNKNOWN_ATTRIBUTE=420,    /* RFC5389 */
  STUN_ERROR_ALLOCATION_MISMATCH=437,   /* TURN-12 */
  STUN_ERROR_STALE_NONCE=438,      /* RFC5389 */
  STUN_ERROR_ACT_DST_ALREADY=439,    /* TURN-04 */
  STUN_ERROR_UNSUPPORTED_FAMILY=440,      /* TURN-IPv6-05 */
  STUN_ERROR_WRONG_CREDENTIALS=441,    /* TURN-12 */
  STUN_ERROR_UNSUPPORTED_TRANSPORT=442,    /* TURN-12 */
  STUN_ERROR_INVALID_IP=443,      /* TURN-04 */
  STUN_ERROR_INVALID_PORT=444,      /* TURN-04 */
  STUN_ERROR_OP_TCP_ONLY=445,      /* TURN-04 */
  STUN_ERROR_CONN_ALREADY=446,      /* TURN-04 */
  STUN_ERROR_ALLOCATION_QUOTA_REACHED=486,    /* TURN-12 */
  STUN_ERROR_ROLE_CONFLICT=487,      /* ICE-19 */
  STUN_ERROR_SERVER_ERROR=500,      /* RFC5389 */
  STUN_ERROR_SERVER_CAPACITY=507,    /* TURN-04 */
  STUN_ERROR_INSUFFICIENT_CAPACITY=508,    /* TURN-12 */
  STUN_ERROR_MAX=699
} StunError;


typedef enum
{
  STUN_MESSAGE_RETURN_SUCCESS,
  STUN_MESSAGE_RETURN_NOT_FOUND,
  STUN_MESSAGE_RETURN_INVALID,
  STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE,
  STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS
} StunMessageReturn;

#include "stunagent.h"
#include "stunhmac.h"
#include "stuncrc32.h"
#include "utils.h"
#include "stun5389.h"

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
bool stun_message_init (StunMessage *msg, StunClass c, StunMethod m,
    const StunTransactionId id);

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
const void * stun_message_find (const StunMessage * msg, StunAttribute type,
    uint16_t *palen);


/**
 * Looks for a flag attribute within a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @return 0 if flag is present, ENOENT if it is not, EINVAL if flag payload
 * size is not zero.
 */
StunMessageReturn stun_message_find_flag (const StunMessage *msg,
    StunAttribute type);

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
StunMessageReturn stun_message_find32 (const StunMessage *msg,
    StunAttribute type, uint32_t *pval);

/**
 * Extracts a 64-bits attribute from a valid STUN message.
 * @param msg valid STUN message buffer
 * @param type STUN attribute type (host byte order)
 * @param pval [OUT] where to store the host byte ordered value
 * @return 0 on success, ENOENT if attribute not found,
 * EINVAL if attribute payload was not 64-bits.
 * In case of error, @a *pval is not modified.
 */
StunMessageReturn stun_message_find64 (const StunMessage *msg,
    StunAttribute type, uint64_t *pval);

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
StunMessageReturn stun_message_find_string (const StunMessage *msg,
    StunAttribute type, char *buf, size_t buflen);

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
StunMessageReturn stun_message_find_addr (const StunMessage *msg,
    StunAttribute type, struct sockaddr *addr, socklen_t *addrlen);

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
StunMessageReturn stun_message_find_xor_addr (const StunMessage *msg,
    StunAttribute type, struct sockaddr *addr, socklen_t *addrlen);

StunMessageReturn stun_message_find_xor_addr_full (const StunMessage *msg,
    StunAttribute type, struct sockaddr *addr,
    socklen_t *addrlen, uint32_t magic_cookie);


StunMessageReturn stun_message_find_error (const StunMessage *msg, int *code);

void *stun_message_append (StunMessage *msg, StunAttribute type,
    size_t length);

StunMessageReturn stun_message_append_bytes (StunMessage *msg,
    StunAttribute type, const void *data, size_t len);

/**
 * Appends an empty ("flag") attribute to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
StunMessageReturn stun_message_append_flag (StunMessage *msg,
    StunAttribute type);

/**
 * Appends an attribute consisting of a 32-bits value to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param value payload (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
StunMessageReturn stun_message_append32 (StunMessage *msg,
    StunAttribute type, uint32_t value);

/**
 * Appends an attribute consisting of a 64-bits value to a STUN message.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param value payload (host byte order)
 * @return 0 on success, ENOBUFS on error.
 */
StunMessageReturn stun_message_append64 (StunMessage *msg,
    StunAttribute type, uint64_t value);

/**
 * Appends an attribute from a nul-terminated string.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param type attribute type (host byte order)
 * @param str nul-terminated string
 * @return 0 on success, ENOBUFS on error.
 */
StunMessageReturn stun_message_append_string (StunMessage *msg,
    StunAttribute type, const char *str);

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
StunMessageReturn stun_message_append_addr (StunMessage * msg,
    StunAttribute type, const struct sockaddr *addr, socklen_t addrlen);

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
StunMessageReturn stun_message_append_xor_addr (StunMessage * msg,
    StunAttribute type, const struct sockaddr *addr, socklen_t addrlen);

StunMessageReturn stun_message_append_xor_addr_full (StunMessage * msg,
    StunAttribute type, const struct sockaddr *addr, socklen_t addrlen,
    uint32_t magic_cookie);

/**
 * Appends an ERROR-CODE attribute.
 * @param msg STUN message buffer
 * @param msize STUN message buffer size
 * @param code STUN host-byte order integer error code
 * @return 0 on success, or ENOBUFS otherwise
 */
StunMessageReturn stun_message_append_error (StunMessage * msg,
    StunError code);

#define STUN_MESSAGE_BUFFER_INCOMPLETE 0
#define STUN_MESSAGE_BUFFER_INVALID -1


int stun_message_validate_buffer_length (const uint8_t *msg, size_t length);

void stun_message_id (const StunMessage *msg, StunTransactionId id);

StunClass stun_message_get_class (const StunMessage *msg);
StunMethod stun_message_get_method (const StunMessage *msg);
bool stun_message_has_attribute (const StunMessage *msg, StunAttribute type);

#endif /* _STUN_MESSAGE_H */
