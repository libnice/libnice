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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif


static void fatal (const char *msg, ...)
{
  va_list ap;
  va_start (ap, msg);
  vfprintf (stderr, msg, ap);
  va_end (ap);
  fputc ('\n', stderr);
  exit (1);
}

static const uint8_t usr[] = "admin";
static const uint8_t pwd[] = "s3kr3t";

static bool dynamic_check_validater (StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data)
{

  if (username_len != strlen ((char *) usr) ||
      memcmp (username, usr, strlen ((char *) usr)) != 0)
    fatal ("vector test : Validater received wrong username!");

  *password = (uint8_t *) pwd;
  *password_len = strlen ((char *) pwd);


  return true;
}
static void
dynamic_check (StunAgent *agent, StunMessage *msg, size_t len)
{
  StunMessage msg2;

  if (stun_agent_validate (agent, &msg2, msg->buffer, len, dynamic_check_validater, NULL) != STUN_VALIDATION_SUCCESS)
    fatal ("Could not validate message");

  printf ("Built message of %u bytes\n", (unsigned)len);
}


static size_t
finish_check (StunAgent *agent, StunMessage *msg)
{
  uint8_t buf[STUN_MAX_MESSAGE_SIZE + 8];
  size_t len;
  uint16_t plen;
  StunMessage msg2 = {0};
  msg2.agent = msg->agent;
  msg2.buffer = buf;
  msg2.buffer_len = sizeof(buf);
  memcpy (msg2.buffer, msg->buffer, sizeof(buf) > msg->buffer_len ? msg->buffer_len : sizeof(buf));

  len = stun_agent_finish_message (agent, msg, NULL, 0);

  if (len <= 0)
    fatal ("Cannot finish message");
  dynamic_check (agent, msg, len);

  if (stun_message_find (&msg2, STUN_ATTRIBUTE_MESSAGE_INTEGRITY, &plen) != NULL)
    fatal ("Missing HMAC test failed");

  stun_message_append_string (&msg2, STUN_ATTRIBUTE_USERNAME, (char *) usr);

  len = stun_agent_finish_message (agent, &msg2, pwd, strlen ((char *) pwd));

  if (len <= 0)
    fatal ("Cannot finish message with short-term creds");
  dynamic_check (agent, &msg2, len);

  return len;
}

static void
check_af (const char *name, int family, socklen_t addrlen)
{
  struct sockaddr_storage addr;
  uint8_t buf[100];
  StunAgent agent;
  StunMessage msg;
  uint16_t known_attributes[] = {STUN_ATTRIBUTE_USERNAME, STUN_ATTRIBUTE_MESSAGE_INTEGRITY, STUN_ATTRIBUTE_ERROR_CODE, 0};

  stun_agent_init (&agent, known_attributes,
      STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_USE_FINGERPRINT);

  assert (addrlen <= sizeof (addr));

  memset (&addr, 0, sizeof (addr));
  stun_agent_init_request (&agent, &msg, buf, sizeof(buf), STUN_BINDING);

  if (stun_message_append_addr (&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS,
          (struct sockaddr *) &addr, addrlen) !=
      STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS)
    fatal ("Unknown address family test failed");
  if (stun_message_append_xor_addr (&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
          &addr, addrlen) !=
      STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS)
    fatal ("Unknown address family xor test failed");

  addr.ss_family = family;
  if (stun_message_append_addr (&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS,
          (struct sockaddr *) &addr, addrlen - 1) !=
      STUN_MESSAGE_RETURN_INVALID)
    fatal ("Too small %s sockaddr test failed", name);

  if (stun_message_append_xor_addr (&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
          &addr, addrlen - 1) != STUN_MESSAGE_RETURN_INVALID)
    fatal ("Too small %s sockaddr xor test failed", name);

  if (stun_message_append_addr (&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS,
          (struct sockaddr *) &addr, addrlen) != STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("%s sockaddr test failed", name);

  if (stun_message_append_xor_addr (&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
          &addr, addrlen) != STUN_MESSAGE_RETURN_SUCCESS)
    fatal ("%s sockaddr xor test failed", name);
}

int main (void)
{
  uint8_t buf[100];
  size_t len;
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } addr;

  StunAgent agent;
  StunMessage msg;
  uint16_t known_attributes[] = {STUN_ATTRIBUTE_USERNAME,
                                 STUN_ATTRIBUTE_MESSAGE_INTEGRITY,
                                 STUN_ATTRIBUTE_ERROR_CODE,
                                 0};

  stun_agent_init (&agent, known_attributes,
      STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_USE_FINGERPRINT);

  /* Request formatting test */
  stun_agent_init_request (&agent, &msg, buf, sizeof(buf), STUN_BINDING);
  finish_check (&agent, &msg);
  if (memcmp (buf, "\x00\x01", 2))
    fatal ("Request formatting test failed");

  /* Response formatting test */
  stun_agent_init_response (&agent, &msg, buf, sizeof (buf), &msg);
  finish_check (&agent, &msg);
  if (memcmp (buf, "\x01\x01", 2))
    fatal ("Response formatting test failed");

  /* Error formatting test */
  stun_agent_init_request (&agent, &msg, buf, sizeof(buf), STUN_BINDING);
  finish_check (&agent, &msg);
  if (!stun_agent_init_error (&agent, &msg, buf, sizeof (buf), &msg, 400))
    fatal ("Error initialization test failed");
  finish_check (&agent, &msg);
  if (memcmp (buf, "\x01\x11", 2))
    fatal ("Error formatting test failed");
  /* Unknown error formatting test */
  stun_agent_init_request (&agent, &msg, buf, sizeof(buf), STUN_BINDING);
  finish_check (&agent, &msg);
  if (!stun_agent_init_error (&agent, &msg, buf, sizeof (buf), &msg, 666))
    fatal ("Unknown error initialization test failed");
  finish_check (&agent, &msg);
  if (memcmp (buf, "\x01\x11", 2))
    fatal ("Unknown error formatting test failed");

  /* Overflow tests */
  stun_agent_init_request (&agent, &msg, buf, sizeof(buf), STUN_BINDING);

  for (len = 0;
       stun_message_append_flag (&msg, 0xffff) !=
           STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE;
       len += 4)
  {
    if (len > 0xffff)
      fatal ("Overflow protection test failed");
  }

  if (stun_message_append32 (&msg, 0xffff, 0x12345678) !=
      STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE)
    fatal ("Double-word overflow test failed");
  if (stun_message_append64 (&msg, 0xffff,
          0x123456789abcdef0) != STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE)
    fatal ("Quad-word overflow test failed");
  if (stun_message_append_string (&msg, 0xffff, "foobar") !=
      STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE)
    fatal ("String overflow test failed");

  memset (&addr, 0, sizeof (addr));
  addr.addr.sa_family = AF_INET;
#ifdef HAVE_SS_LEN
  addr.addr.ss_len = sizeof (addr);
#endif
  if (stun_message_append_xor_addr (&msg, 0xffff, &addr.storage,
          sizeof (addr)) != STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE)
    fatal ("Address overflow test failed");
  len = sizeof (msg);
  if (stun_agent_finish_message (&agent, &msg, NULL, 0) != 0)
    fatal ("Fingerprint overflow test failed");
  if (stun_agent_finish_message (&agent, &msg, pwd, strlen ((char *) pwd)) != 0)
    fatal ("Message integrity overflow test failed");

  /* Address attributes tests */
  check_af ("IPv4", AF_INET, sizeof (struct sockaddr_in));
#ifdef AF_INET6
  check_af ("IPv6", AF_INET6, sizeof (struct sockaddr_in6));
#endif

  return 0;
}
