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

# define STUN_COOKIE 0x2112A442
# ifndef IPPORT_STUN
#  define IPPORT_STUN  3478
# endif

typedef struct stun_hdr_s
{
	uint16_t  msg_type;
	uint16_t  msg_len;
	uint32_t  msg_cookie;
	uint32_t  msg_id[3];
} stun_hdr_t;


typedef struct stun_s
{
	stun_hdr_t hdr;
	uint8_t buf[65532];
} stun_msg_t;

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
	STUN_BINDING=0x001,
	STUN_SHARED_SECRET=0x002
} stun_method_t;

/* Attribute types */
typedef enum
{
	/* Mandatory attributes */
	STUN_MAPPED_ADDRESS=0x0001,
	STUN_OLD_RESPONSE_ADDRESS=0x0002,
	STUN_OLD_CHANGE_REQUEST=0x0003,
	STUN_OLD_SOURCE_ADDRESS=0x0004,
	STUN_OLD_CHANGED_ADDRESS=0x0005,
	STUN_USERNAME=0x0006,
	STUN_PASSWORD=0x0007,
	STUN_MESSAGE_INTEGRITY=0x0008,
	STUN_ERROR_CODE=0x0009,
	STUN_UNKNOWN_ATTRIBUTES=0x000A,
	STUN_OLD_REFLECTED_FROM=0x000B,

	STUN_REALM=0x0014,
	STUN_NONCE=0x0015,

	STUN_XOR_MAPPED_ADDRESS=0x0020,

	/* Optional attributes */
	STUN_FINGERPRINT=0x8021, // FIXME: rfc3489bis-06 has wrong value
    STUN_SERVER=0x8022,
	STUN_ALTERNATE_SERVER=0x8023,
	STUN_REFRESH_INTERVAL=0x8024
} stun_attr_type_t;


static inline int stun_optional (stun_attr_type_t t)
{
	return t >> 15;
}

typedef uint8_t stun_transid_t[12];

typedef struct stun_attr_hdr_s
{
	uint16_t attr_type;
	uint16_t attr_len;
	uint8_t  attr_value[0];
} stun_attr_hdr_t;

/* MESSAGE-INTEGRITY */
typedef struct stun_attr_integrity_s
{
	stun_attr_hdr_t int_hdr;
	uint8_t         int_hmac[20];
} stun_attr_integrity_t;

/* ERROR-CODE */
typedef struct stun_attr_error_s
{
	stun_attr_hdr_t err_hdr;
	unsigned        err_zero:21;
	unsigned        err_class:3;
	uint8_t         err_number;
} stun_attr_error_t;

/* Error codes */
# define STUN_TRY_ALTERNATE           300
# define STUN_BAD_REQUEST             400
# define STUN_UNAUTHORIZED            401
# define STUN_UNKNOWN_ATTRIBUTE       420
# define STUN_STALE_CREDENTIALS       430
# define STUN_INTEGRITY_CHECK_FAILURE 431
# define STUN_MISSING_USERNAME        432
# define STUN_USE_TLS                 433
# define STUN_MISSING_REALM           434
# define STUN_MISSING_NONCE           435
# define STUN_UNKNOWN_USERNAME        436
# define STUN_STALE_NONCE             438
# define STUN_SERVER_ERROR            500
# define STUN_GLOBAL_FAILURE          600


/**
 * @return complement to the next multiple of 4.
 */
static inline size_t stun_padding (size_t l)
{
	static const size_t pads[4] = { 0, 3, 2, 1 };
	return pads[l & 3];
}

/**
 * Rounds up an integer to the next multiple of 4.
 */
static inline size_t stun_align (size_t l)
{
	return l + stun_padding (l);
}


/**
 * Reads a word from a non-aligned buffer.
 * @return host byte order word value.
 */
static inline uint16_t stun_getw (const void *ptr)
{
	return (((const uint8_t *)ptr)[0] << 8)
	      | ((const uint8_t *)ptr)[1];
}

static inline uint16_t stun_length (const void *ptr)
{
	return stun_getw (((const uint8_t *)ptr) + 2);
}


/**
 * @return STUN message class in host byte order (value from 0 to 3)
 */
static inline uint16_t stun_get_class (const void *msg)
{
	uint16_t t = stun_getw (msg);
	return ((t & 0x0100) >> 7) | ((t & 0x0010) >> 4);
}

/**
 * @return STUN message method (value from 0 to 0xfff)
 */
static inline uint16_t stun_get_method (const void *msg)
{
	uint16_t t = stun_getw (msg);
	return ((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) | (t & 0x000f);
}

# ifdef __cplusplus
extern "C" {
# endif

uint32_t stun_fingerprint (const void *msg);
void stun_sha1 (const void *msg, uint8_t *sha,
                const void *key, size_t keylen);

int stun_xor_address (const void *msg,
                      struct sockaddr *addr, socklen_t addrlen);

/* Message processing functions */
ssize_t stun_validate (const void *msg, size_t len);
bool stun_demux (const void *msg);
bool stun_match_answer (const void *msg, stun_method_t method,
                        const stun_transid_t id, bool *restrict error);
int stun_verify_key (const void *msg, const void *key, size_t keylen);
int stun_verify_password (const void *msg, const char *pw);

/*int stun_find32 (const void *msg, stun_attr_type_t type, uint32_t *pval);*/
int stun_find_addr (const void *restrict msg, stun_attr_type_t type,
                    struct sockaddr *restrict addr,
                    socklen_t *restrict addrlen);
int stun_find_xor_addr (const void *restrict msg, stun_attr_type_t type,
                        struct sockaddr *restrict addr,
                        socklen_t *restrict addrlen);
unsigned stun_find_unknown (const void *msg, uint16_t *list, unsigned max);

/* Message formatting functions */
void stun_init (stun_msg_t *msg, stun_class_t c, stun_method_t m,
                const stun_transid_t id);
void stun_init_response (stun_msg_t *ans, const void *req);
void stun_make_transid (stun_transid_t id);
size_t stun_finish_short (stun_msg_t *restrict msg,
                          const char *username, const char *password,
                          const void *nonce, size_t noncelen);
size_t stun_finish (stun_msg_t *m);

int stun_append32 (stun_msg_t *msg, stun_attr_type_t type,
                       uint32_t value);
int stun_append_addr (stun_msg_t *restrict msg, stun_attr_type_t type,
                      const struct sockaddr *restrict addr,
                      socklen_t addrlen);
int stun_append_xor_addr (stun_msg_t *restrict msg, stun_attr_type_t type,
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

#endif
