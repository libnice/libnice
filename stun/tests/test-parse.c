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

#include "stun/stunagent.h"
#include "stun/stunhmac.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif


# define STUN_MAX_STR (763u)
# define STUN_MAX_CP  (127u)

static void fatal (const char *msg, ...)
{
  va_list ap;
  va_start (ap, msg);
  vfprintf (stderr, msg, ap);
  va_end (ap);
  fputc ('\n', stderr);
  exit (1);
}


static void validate (const uint8_t *msg, unsigned len)
{
  unsigned i = 1;

  do
  {
    size_t vlen = stun_message_validate_buffer_length (msg, i, TRUE);
    if ((vlen & 3) || (vlen != ((i >= len) * len)))
      fatal ("%u/%u short message test failed", i, len);
  }
  while (i++ < (len + 4));
}


/* Tests for generic message validation routines */
static void test_message (void)
{
  static const uint8_t extra_garbage[] =
      {0x15, 0x55, 0x00, 0x00,
       0x21, 0x12, 0xA4, 0x42, // cookie
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10,
       0xaa, 0xbb, 0xcc, 0xdd}; //extra garbage
  static const uint8_t simple_resp[] =
      {0x15, 0x55, 0x00, 0x00,
       0x21, 0x12, 0xA4, 0x42, // cookie
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10};
  static const uint8_t old_ind[] =
      {0x14, 0x55, 0x00, 0x00,
       0xfe, 0xdc, 0xba, 0x98, // NO cookie
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10};
  static const uint8_t fpr_resp[] =
      {0x15, 0x55, 0x00, 0x10,
       0x21, 0x12, 0xA4, 0x42, // cookie
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10,
       0x00, 0x06, 0x00, 0x04, // dummy USERNAME header
       0x41, 0x42, 0x43, 0x44,
       0x80, 0x28, 0x00, 0x04, // FINGERPRINT header
       0xdc, 0x8d, 0xa7, 0x74}; // CRC32;
  static const uint8_t bad1[32] =
      {0x15, 0x55, 0x00, 0x08,
       0x21, 0x12, 0xA4, 0x42, // cookie
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10,
       0x00, 0x06, 0x00, 0x05, // too big attribute for message
       0x11, 0x22, 0x33, 0x44,
       0x55, 0x66, 0x77, 0x88};
  static const uint8_t bad2[24] =
      {0x15, 0x55, 0x00, 0x05, // invalid message length
       0x21, 0x12, 0xA4, 0x42,
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10,
       0x00, 0x06, 0x00, 0x01};
  static const uint8_t bad3[27] =
      {0x15, 0x55, 0x00, 0x08,
       0x21, 0x12, 0xA4, 0x42,
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10,
       0x00, 0x06, 0x00, 0x03,
       0x11, 0x22, 0x33}; // missing padding
  static const uint8_t bad_crc[] =
      {0x15, 0x55, 0x00, 0x08,
       0x21, 0x12, 0xA4, 0x42,
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10,
       0x80, 0x28, 0x00, 0x04, // FINGERPRINT header
       0x04, 0x91, 0xcd, 0x78}; // CRC32
  static uint8_t bad_crc_offset[] =
      {0x15, 0x55, 0x00, 0x10,
       0x21, 0x12, 0xA4, 0x42,
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x20, 0x67, 0xc4, 0x09,
       0x80, 0x28, 0x00, 0x04, // FINGERPRINT header
       0x00, 0x00, 0x00, 0x00,
       0x00, 0x06, 0x00, 0x04,
       0x41, 0x42, 0x43, 0x44};

  static unsigned char req[] =
      {0x00, 0x01, 0x00, 0x00,
       0x8b, 0x45, 0x9b, 0xc3,
       0xe7, 0x7a, 0x05, 0xb3,
       0xe4, 0xfe, 0x01, 0xf0,
       0xaf, 0x83, 0xe1, 0x9e};

  static uint8_t binding_error_resp[] =
      {0x01, 0x11, 0x00, 0x84,
       0x8b, 0x45, 0x9b, 0xc3,
       0xe7, 0x7a, 0x05, 0xb3,
       0xe4, 0xfe, 0x01, 0xf0,
       0xaf, 0x83, 0xe1, 0x9e,

       0x00, 0x06, 0x00, 0x48, // USERNAME
       0x92, 0x6b, 0x2b, 0x3e,
       0x6a, 0xa5, 0x43, 0x58,
       0xa8, 0x51, 0x25, 0xa6,
       0xf7, 0x9c, 0x0a, 0xe7,
       0xd8, 0x86, 0xf7, 0x76,
       0xf9, 0xcd, 0x8a, 0x2e,
       0x45, 0xd7, 0xcb, 0xbb,
       0xae, 0xe5, 0x03, 0xc3,
       0x3a, 0x32, 0x3a, 0xa9,
       0x9e, 0xb7, 0x7b, 0x32,
       0xe3, 0xf3, 0xa6, 0xc0,
       0xe8, 0x54, 0x4b, 0xef,
       0x52, 0xd2, 0xe2, 0xc0,
       0x43, 0xc2, 0x4c, 0xbc,
       0xaf, 0xd9, 0xf2, 0xfa,
       0x48, 0x8b, 0x8c, 0xe6,
       0x62, 0x14, 0x64, 0x3a,
       0x32, 0x00, 0x00, 0x00,

       0x00, 0x09, 0x00, 0x1c, // ERROR-CODE
       0x00, 0x00, 0x04, 0x1f,
       0x49, 0x6e, 0x74, 0x65,
       0x67, 0x72, 0x69, 0x74,
       0x79, 0x20, 0x43, 0x68,
       0x65, 0x63, 0x6b, 0x20,
       0x46, 0x61, 0x69, 0x6c,
       0x75, 0x72, 0x65, 0x2e,

       0x00, 0x08, 0x00, 0x14, // MESSAGE-INTEGRITY
       0xf7, 0x46, 0x81, 0xc4,
       0x6f, 0x4c, 0x21, 0x5c,
       0xf6, 0x8e, 0xc0, 0x81,
       0x0e, 0x20, 0x3f, 0xb1,
       0xb1, 0xad, 0xa4, 0x8a};

  StunAgent agent;
  StunAgent agent2;
  StunMessage msg;
  uint16_t known_attributes[] = {STUN_ATTRIBUTE_USERNAME,
                                 STUN_ATTRIBUTE_ERROR_CODE,
                                 STUN_ATTRIBUTE_MESSAGE_INTEGRITY};

  uint8_t username_v[] = {0x92, 0x6b, 0x2b, 0x3e, 0x6a, 0xa5, 0x43, 0x58,
                          0xa8, 0x51, 0x25, 0xa6, 0xf7, 0x9c, 0x0a, 0xe7,
                          0xd8, 0x86, 0xf7, 0x76, 0xf9, 0xcd, 0x8a, 0x2e,
                          0x45, 0xd7, 0xcb, 0xbb, 0xae, 0xe5, 0x03, 0xc3,
                          0x3a, 0x32, 0x3a, 0xa9, 0x9e, 0xb7, 0x7b, 0x32,
                          0xe3, 0xf3, 0xa6, 0xc0, 0xe8, 0x54, 0x4b, 0xef,
                          0x52, 0xd2, 0xe2, 0xc0, 0x43, 0xc2, 0x4c, 0xbc,
                          0xaf, 0xd9, 0xf2, 0xfa, 0x48, 0x8b, 0x8c, 0xe6,
                          0x62, 0x14, 0x64, 0x3a, 0x32, 0x00, 0x00, 0x00};
  uint8_t password_v[]  = {0x77, 0xd9, 0x7a, 0xe9, 0xcf, 0xe0, 0x3e, 0xa2,
                           0x28, 0xa0, 0x5d, 0xec, 0xcf, 0x36, 0xe8, 0x49};

  StunDefaultValidaterData v = {username_v, 72, password_v, 16};

  stun_agent_init (&agent, known_attributes,
      STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_USE_FINGERPRINT);
  stun_agent_init (&agent2, known_attributes,
      STUN_COMPATIBILITY_RFC3489, STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS);


  stun_agent_validate (&agent2, &msg, req, sizeof(req),  NULL, NULL);
  stun_agent_finish_message (&agent2, &msg, NULL, 0);

  if (stun_agent_validate (&agent2, &msg, binding_error_resp,
          sizeof(binding_error_resp),
          stun_agent_default_validater, &v) != STUN_VALIDATION_SUCCESS)
    fatal ("Binding Error Response failed");


  if (stun_message_validate_buffer_length (NULL, 0, TRUE) !=
      STUN_MESSAGE_BUFFER_INVALID)
    fatal ("0 bytes test failed");
  if (stun_message_validate_buffer_length ((uint8_t *)"\xf0", 1, TRUE) >= 0)
    fatal ("1 byte test failed");
  if (stun_message_validate_buffer_length (bad1, sizeof (bad1), TRUE) >= 0)
    fatal ("Badness 1 test failed");
  if (stun_message_validate_buffer_length (bad2, sizeof (bad2), TRUE) >= 0)
    fatal ("Badness 2 test failed");
  if (stun_message_validate_buffer_length (bad3, sizeof (bad3), TRUE) != 0)
    fatal ("Badness 3 test failed");
  validate (simple_resp, 20);
  validate (old_ind, 20);
  validate (fpr_resp, 36);

  if (stun_agent_validate (&agent, &msg, extra_garbage, sizeof(extra_garbage),
          NULL, NULL) != STUN_VALIDATION_NOT_STUN)
    fatal ("Extra garbage test failed");
  if (stun_agent_validate (&agent, &msg, simple_resp, sizeof(simple_resp),
          NULL, NULL) != STUN_VALIDATION_BAD_REQUEST)
    fatal ("Missing CRC test failed");
  if (stun_agent_validate (&agent, &msg, old_ind, sizeof(old_ind),
          NULL, NULL) != STUN_VALIDATION_BAD_REQUEST)
    fatal ("Missing cookie test failed");
  if (stun_agent_validate (&agent, &msg, bad_crc, sizeof(bad_crc),
          NULL, NULL) != STUN_VALIDATION_BAD_REQUEST)
    fatal ("Bad CRC test failed");
  if (stun_agent_validate (&agent, &msg, bad_crc_offset, sizeof(bad_crc_offset),
          NULL, NULL) != STUN_VALIDATION_BAD_REQUEST)
    fatal ("Bad CRC offset test failed");
  if (stun_agent_validate (&agent, &msg, fpr_resp, sizeof(fpr_resp),
          NULL, NULL) != STUN_VALIDATION_UNMATCHED_RESPONSE)
    fatal ("Good CRC test failed");

  if (stun_message_get_class (&msg) != 3)
    fatal ("Class test failed");
  if (stun_message_get_method (&msg) != 0x525)
    fatal ("Method test failed");
}


static bool test_attribute_validater (StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data)
{
  uint8_t *pwd = user_data;

  if (username_len != 4 ||
      memcmp (username, "ABCD", 4) != 0)
    return false;

  *password = pwd;
  *password_len = strlen ((char *) pwd);

  return true;
}

/* Tests for message attribute parsing */
static void test_attribute (void)
{
  static const uint8_t acme[] =
      {0x04, 0x55, 0x00, 0x6C, // <-- update message length if needed!!
       0x21, 0x12, 0xA4, 0x42, // cookie
       0x76, 0x54, 0x32, 0x10,
       0xfe, 0xdc, 0xba, 0x98,
       0x76, 0x54, 0x32, 0x10,

       /* FF01: empty */
       0xff, 0x01, 0x00, 0x00,

       /* FF02: address of unknown family, 32-bits */
       0xff, 0x02, 0x00, 0x04,
       0x41, 0x42, 0x43, 0x44,

       /* FF03: too short IPv6 address */
       0xff, 0x03, 0x00, 0x06,
       0x00, 0x02, 0x12, 0x34,
       0x20, 0x01, 0x0d, 0xb8,

       /* FF04: valid IPv4 address, 64-bits */
       0xff, 0x04, 0x00, 0x08,
       0x00, 0x01, 0x12, 0x34,
       0xc0, 0x00, 0x02, 0x01,

       /* FF05: too long IPv4 address */
       0xff, 0x05, 0x00, 0x0A,
       0x00, 0x01, 0x12, 0x34,
       0xc0, 0x00, 0x02, 0x01,
       0x66, 0x60, 0x00, 0x00,

       /* FF06: valid xor'd IPv6 address, 160-bits */
       0xff, 0x06, 0x00, 0x14,
       0x00, 0x02, 0x12, 0x34,
       0x01, 0x13, 0xa9, 0xfa,
       0xa8, 0xf9, 0x8c, 0xff,
       0x20, 0x26, 0x74, 0x48,
       0x8c, 0x9a, 0xec, 0xfd,

       /* dummy USERNAME header */
       0x00, 0x06, 0x00, 0x04,
       0x41, 0x42, 0x43, 0x44,

       /* MESSAGE-INTEGRITY attribute */
       0x00, 0x08, 0x00, 0x14,
       0x0b, 0xc4, 0xb2, 0x0c,
       0x94, 0x58, 0xbb, 0x25,
       0xa3, 0x22, 0x1a, 0xc8,
       0xe1, 0x87, 0x32, 0x36,
       0x3a, 0xfc, 0xe2, 0xc3};

  union
  {
    struct sockaddr_storage st;
    struct sockaddr_in6 s6;
  } addr;
  socklen_t addrlen;
  uint32_t dword;
  uint64_t qword;
  char str[STUN_MAX_STR];

  StunAgent agent;
  StunMessage msg;
  uint16_t known_attributes[] = {STUN_ATTRIBUTE_MESSAGE_INTEGRITY, STUN_ATTRIBUTE_USERNAME, 0};

  printf ("Attribute test message length: %zd\n", sizeof (acme));

  stun_agent_init (&agent, known_attributes,
      STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS);

  if (stun_agent_validate (&agent, &msg, acme, sizeof(acme),
          NULL, NULL) != STUN_VALIDATION_UNAUTHORIZED)
    fatal ("Unauthorized validation failed");

  if (stun_agent_validate (&agent, &msg, acme, sizeof(acme),
          test_attribute_validater, (void *) "bad__guy") != STUN_VALIDATION_UNAUTHORIZED)
    fatal ("invalid password validation failed");

  if (stun_agent_validate (&agent, &msg, acme, sizeof(acme),
          test_attribute_validater, (void *) "good_guy") != STUN_VALIDATION_SUCCESS)
    fatal ("good password validation failed");

  if (stun_message_has_attribute (&msg, 0xff00))
    fatal ("Absent attribute test failed");
  if (!stun_message_has_attribute (&msg, 0xff01))
    fatal ("Present attribute test failed");

  if (stun_message_find_flag (&msg, 0xff00) != STUN_MESSAGE_RETURN_NOT_FOUND)
    fatal ("Absent flag test failed");
  if (stun_message_find_flag (&msg, 0xff01) != STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("Flag test failed");
  if (stun_message_find_flag (&msg, 0xff02) != STUN_MESSAGE_RETURN_INVALID)
    fatal ("Too big flag test failed");

  if (stun_message_find32 (&msg, 0xff00, &dword) !=
      STUN_MESSAGE_RETURN_NOT_FOUND)
    fatal ("Absent dword test failed");
  if (stun_message_find32 (&msg, 0xff01, &dword) != STUN_MESSAGE_RETURN_INVALID)
    fatal ("Bad dword test failed");
  if (stun_message_find32 (&msg, 0xff02, &dword) != STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("Double-word test failed");

  if (stun_message_find64 (&msg, 0xff00, &qword) !=
      STUN_MESSAGE_RETURN_NOT_FOUND)
    fatal ("Absent qword test failed");
  if (stun_message_find64 (&msg, 0xff01, &qword) != STUN_MESSAGE_RETURN_INVALID)
    fatal ("Bad qword test failed");
  if (stun_message_find64 (&msg, 0xff04, &qword) != STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("Quad-word test failed");

  if (stun_message_find_string (&msg, 0xff00, str, STUN_MAX_CP) !=
      STUN_MESSAGE_RETURN_NOT_FOUND)
    fatal ("Absent string test failed");
  if ((stun_message_find_string (&msg, 0xff02, str, STUN_MAX_CP) !=
          STUN_MESSAGE_RETURN_SUCCESS)
   || strcmp (str, "ABCD"))
    fatal ("String test failed");

  addrlen = sizeof (addr);
  if (stun_message_find_addr (&msg, 0xff01, &addr.st, &addrlen) !=
      STUN_MESSAGE_RETURN_INVALID)
    fatal ("Too short addres test failed");
  addrlen = sizeof (addr);
  if (stun_message_find_addr (&msg, 0xff02, &addr.st, &addrlen) !=
      STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS)
    fatal ("Unknown address family test failed");
  addrlen = sizeof (addr);
  if (stun_message_find_addr (&msg, 0xff03, &addr.st, &addrlen) !=
      STUN_MESSAGE_RETURN_INVALID)
    fatal ("Too short IPv6 address test failed");
  addrlen = sizeof (addr);
  if (stun_message_find_addr (&msg, 0xff04, &addr.st, &addrlen) !=
      STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("IPv4 address test failed");
  addrlen = sizeof (addr);
  if (stun_message_find_addr (&msg, 0xff05, &addr.st, &addrlen) !=
      STUN_MESSAGE_RETURN_INVALID)
    fatal ("Too big IPv4 address test failed");
  addrlen = sizeof (addr);
  if (stun_message_find_xor_addr (&msg, 0xff06, &addr.st, &addrlen) !=
      STUN_MESSAGE_RETURN_SUCCESS ||
      memcmp (&addr.s6.sin6_addr, "\x20\x01\x0d\xb8""\xde\xad\xbe\xef"
                                  "\xde\xfa\xce\xd0""\xfa\xce\xde\xed", 16))
    fatal ("IPv6 address test failed");

}

static const char vector_username[] = "evtj:h6vY";
static uint8_t vector_password[] = "VOkJxbRl1RmTxUk/WvJxBt";

static bool test_vector_validater (StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data)
{
  intptr_t callable = (intptr_t) user_data;

  if (!callable)
    fatal ("vector test : Validater should not be called!");

  if (username_len != strlen (vector_username) ||
      memcmp (username, vector_username, strlen (vector_username)) != 0)
    fatal ("vector test : Validater received wrong username!");

  *password = vector_password;
  *password_len = strlen ((char *) vector_password);


  return true;
}

static void test_vectors (void)
{
  /* Request message */
  static unsigned char req[] =
      {0x00, 0x01, 0x00, 0x44,
       0x21, 0x12, 0xa4, 0x42,
       0xb7, 0xe7, 0xa7, 0x01,
       0xbc, 0x34, 0xd6, 0x86,
       0xfa, 0x87, 0xdf, 0xae,

       0x00, 0x24, 0x00, 0x04, // PRIORITY
       0x6e, 0x00, 0x01, 0xff,

       0x80, 0x29, 0x00, 0x08, // ICE_CONTROLLED
       0x93, 0x2f, 0xf9, 0xb1,
       0x51, 0x26, 0x3b, 0x36,

       0x00, 0x06, 0x00, 0x09, // USERNAME
       0x65, 0x76, 0x74, 0x6a,
       0x3a, 0x68, 0x36, 0x76,
       0x59, 0x20, 0x20, 0x20,

       0x00, 0x08, 0x00, 0x14, // MESSAGE_INTEGRITY
       0x62, 0x4e, 0xeb, 0xdc,
       0x3c, 0xc9, 0x2d, 0xd8,
       0x4b, 0x74, 0xbf, 0x85,
       0xd1, 0xc0, 0xf5, 0xde,
       0x36, 0x87, 0xbd, 0x33,

       0x80, 0x28, 0x00, 0x04, // FINGERPRINT
       0xad, 0x8a, 0x85, 0xff};

  static const unsigned char req2[] =
      {0x00, 0x01, 0x00, 0x44,
       0x21, 0x12, 0xa4, 0x42,
       0xb7, 0xe7, 0xa7, 0x01,
       0xbc, 0x34, 0xd6, 0x86,
       0xfa, 0x87, 0xdf, 0xae,

       0x00, 0x24, 0x00, 0x04, // PRIORITY
       0x6e, 0x00, 0x01, 0xff,

       0x80, 0x29, 0x00, 0x08, // ICE_CONTROLLED
       0x93, 0x2f, 0xf9, 0xb1,
       0x51, 0x26, 0x3b, 0x36,

       0x00, 0x06, 0x00, 0x09, // USERNAME
       0x65, 0x76, 0x74, 0x6a,
       0x3a, 0x68, 0x36, 0x76,
       0x59, 0x20, 0x20, 0x20,

       0x00, 0x08, 0x00, 0x14, // MESSAGE_INTEGRITY
       0x62, 0x4e, 0xeb, 0xdc,
       0x3c, 0xc9, 0x2d, 0xd8,
       0x4b, 0x74, 0xbf, 0x85,
       0xd1, 0xc0, 0xf5, 0xde,
       0x36, 0x87, 0xbd, 0x33,

       0x80, 0x28, 0x00, 0x04, // FINGERPRINT
       0xad, 0x8a, 0x85, 0xff};

  /* Response message */
  static const unsigned char respv4[] =
      {0x01, 0x01, 0x00, 0x4c,
       0x21, 0x12, 0xa4, 0x42,
       0xb7, 0xe7, 0xa7, 0x01,
       0xbc, 0x34, 0xd6, 0x86,
       0xfa, 0x87, 0xdf, 0xae,

       0x80, 0x22, 0x00, 0x0b, // SERVER
       0x74, 0x65, 0x73, 0x74,
       0x20, 0x76, 0x65, 0x63,
       0x74, 0x6f, 0x72, 0x20,

       0x00, 0x20, 0x00, 0x08, // XOR_MAPPED_ADDRESS
       0x00, 0x01, 0xa1, 0x47,
       0xe1, 0x12, 0xa6, 0x43,

       0x00, 0x06, 0x00, 0x09, // USERNAME
       0x65, 0x76, 0x74, 0x6a,
       0x3a, 0x68, 0x36, 0x76,
       0x59, 0x20, 0x20, 0x20,

       0x00, 0x08, 0x00, 0x14, // MESSAGE_INTEGRITY
       0x7d, 0xb7, 0xfc, 0x52,
       0x70, 0xc6, 0xdb, 0x1f,
       0xc3, 0x26, 0x34, 0xbb,
       0x4c, 0x64, 0x6e, 0xe7,
       0x1d, 0xb3, 0x78, 0x4a,

       0x80, 0x28, 0x00, 0x04, // FINGERPRINT
       0xf0, 0x60, 0x66, 0xa9};
  static const unsigned char respv6[] =
      {0x01, 0x01, 0x00, 0x58,
       0x21, 0x12, 0xa4, 0x42,
       0xb7, 0xe7, 0xa7, 0x01,
       0xbc, 0x34, 0xd6, 0x86,
       0xfa, 0x87, 0xdf, 0xae,

       0x80, 0x22, 0x00, 0x0b, // SERVER
       0x74, 0x65, 0x73, 0x74,
       0x20, 0x76, 0x65, 0x63,
       0x74, 0x6f, 0x72, 0x20,

       0x00, 0x20, 0x00, 0x14, // XOR_MAPPED_ADDRESS
       0x00, 0x02, 0xa1, 0x47,
       0x01, 0x13, 0xa9, 0xfa,
       0xa5, 0xd3, 0xf1, 0x79,
       0xbc, 0x25, 0xf4, 0xb5,
       0xbe, 0xd2, 0xb9, 0xd9,

       0x00, 0x06, 0x00, 0x09, // USERNAME
       0x65, 0x76, 0x74, 0x6a,
       0x3a, 0x68, 0x36, 0x76,
       0x59, 0x20, 0x20, 0x20,

       0x00, 0x08, 0x00, 0x14, // MESSAGE_INTEGRITY
       0x21, 0xcb, 0xbd, 0x25,
       0x1a, 0x8c, 0x4c, 0x38,
       0x8c, 0xc5, 0xcd, 0xb3,
       0x27, 0x6a, 0xf5, 0x61,
       0xb2, 0x21, 0xc8, 0x2b,

       0x80, 0x28, 0x00, 0x04, // FINGERPRINT
       0xec, 0x27, 0xae, 0xb7};
  union {
    struct sockaddr_storage st;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
  } addr;
  socklen_t addrlen;

  StunAgent agent;
  StunMessage msg;
  StunMessage msg2;
  uint16_t known_attributes[] = {
    STUN_ATTRIBUTE_MESSAGE_INTEGRITY,
    STUN_ATTRIBUTE_USERNAME,
    STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_PRIORITY, 0};

  stun_agent_init (&agent, known_attributes,
      STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
      STUN_AGENT_USAGE_USE_FINGERPRINT);

  memset (&addr, 0, sizeof (addr));

  puts ("Checking test vectors...");

  if (stun_agent_validate (&agent, &msg2, req2, sizeof(req2),
          test_vector_validater, (void *) 1) != STUN_VALIDATION_SUCCESS)
    fatal ("Request test vector authentication failed");

  if (stun_agent_validate (&agent, &msg, req, sizeof(req),
          test_vector_validater, (void *) 1) != STUN_VALIDATION_SUCCESS)
    fatal ("Request test vector authentication failed");

  /* Remove the message-integrity and fingerprint attributes */
  req[3] = 0x24;

  if (stun_message_length (&msg) != sizeof(req) - 32)
    fatal ("vector test: removing attributes failed");

  stun_agent_finish_message (&agent, &msg, vector_password,
      strlen ((char *) vector_password));

  if (stun_message_length (&msg) != stun_message_length (&msg2) ||
      memcmp (req, req2, sizeof(req)) != 0)
    fatal ("vector test : req and req2 are different");

  if (stun_agent_validate (&agent, &msg, respv4, sizeof(respv4),
          test_vector_validater, (void *) 0) != STUN_VALIDATION_SUCCESS)
    fatal ("Response ipv4 test vector authentication failed");

  if (stun_agent_validate (&agent, &msg, respv4, sizeof(respv4),
          test_vector_validater, (void *) 0) != STUN_VALIDATION_UNMATCHED_RESPONSE)
    fatal ("Response ipv4 test vector authentication failed");

  addrlen = sizeof (addr.ip4);
  if (stun_message_find_xor_addr (&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
          &addr.st, &addrlen) != STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("Response test vector IPv4 extraction failed");
  if (addr.ip4.sin_family != AF_INET)
    fatal ("Response test vector IPv4 family failed");
  if (ntohl (addr.ip4.sin_addr.s_addr) != 0xC0000201)
    fatal ("Response test vector IPv4 address failed");
  if (ntohs (addr.ip4.sin_port) != 32853)
    fatal ("Response test vector IPv6 port failed");

  if (stun_agent_validate (&agent, &msg, req, sizeof(req),
          test_vector_validater, (void *) 1) != STUN_VALIDATION_SUCCESS)
    fatal ("Request test vector second authentication failed");

  /* Remove the fingerprint attributes */
  msg.key = NULL;
  msg.key_len = 0;
  req[3] = 0x3C;

  if (stun_message_length (&msg) != sizeof(req) - 8)
    fatal ("vector test: removing attributes failed");

  stun_agent_finish_message (&agent, &msg, NULL, 0);

  if (stun_message_length (&msg) != stun_message_length (&msg2) ||
      memcmp (req, req2, sizeof(req)) != 0)
    fatal ("vector test : req and req2 are different");

  if (stun_agent_validate (&agent, &msg, respv6, sizeof(respv6),
          test_vector_validater, (void *) 1) != STUN_VALIDATION_SUCCESS)
    fatal ("Response ipv6 test vector authentication failed");

  addrlen = sizeof (addr.ip6);
  if (stun_message_find_xor_addr (&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
          &addr.st, &addrlen) != STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("Response test vector IPv6 extraction failed");
  if (addr.ip6.sin6_family != AF_INET6)
    fatal ("Response test vector IPv6 family failed");
  if (memcmp (addr.ip6.sin6_addr.s6_addr, "\x20\x01\x0d\xb8\x12\x34\x56\x78"
              "\x00\x11\x22\x33\x44\x55\x66\x77", 16) != 0)
    fatal ("Response test vector IPv6 address failed");
  if (ntohs (addr.ip6.sin6_port) != 32853)
    fatal ("Response test vector IPv6 port failed");


  puts ("Done.");
}

static void test_hash_creds (void)
{
  uint8_t md5[16];
  uint8_t real_md5[] = {
    0x84, 0x93, 0xfb, 0xc5,
    0x3b, 0xa5, 0x82, 0xfb,
    0x4c, 0x04, 0x4c, 0x45,
    0x6b, 0xdc, 0x40, 0xeb};

  puts ("Testing long term credentials hash algorithm...");


  stun_hash_creds ((uint8_t *) "realm", strlen ("realm"),
      (uint8_t *) "user",  strlen ("user"),
      (uint8_t *) "pass", strlen ("pass"), md5);

  stun_debug_bytes ("key for user:realm:pass is : ", md5, 16);

  stun_debug_bytes ("RFC key for user:realm:pass is : ", real_md5, 16);

  if(memcmp (md5, real_md5, sizeof(md5)) != 0)
    fatal ("MD5 hashes are different!");

  puts ("Done!");

}

int main (void)
{
  test_message ();
  test_attribute ();
  test_vectors ();
  test_hash_creds ();
  return 0;
}
