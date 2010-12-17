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
#include "stun/usages/turn.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define MSG_DONTWAIT 0
#define MSG_NOSIGNAL 0

#define alarm(...)
#define close closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#endif

#undef NDEBUG /* ensure assertions are built-in */
#include <assert.h>


static int listen_dgram (void)
{
  struct addrinfo hints, *res;
  int val = -1;

  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;

  if (getaddrinfo (NULL, "0", &hints, &res))
    return -1;

  for (const struct addrinfo *ptr = res; ptr != NULL; ptr = ptr->ai_next)
  {
    int fd = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (fd == -1)
      continue;

    if (bind (fd, ptr->ai_addr, ptr->ai_addrlen))
    {
      close (fd);
      continue;
    }

    val = fd;
    break;
  }

  freeaddrinfo (res);
  return val;
}


static void
printaddr (const char *str, const struct sockaddr *addr, socklen_t addrlen)
{
  char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];

  int val = getnameinfo (addr, addrlen, hostbuf, sizeof (hostbuf),
                         servbuf, sizeof (servbuf),
                         NI_NUMERICHOST | NI_NUMERICSERV);
  if (val)
    printf ("%s: %s\n", str, gai_strerror (val));
  else
    printf ("%s: %s port %s\n", str, hostbuf, servbuf);
}


/** Various responses test */
static void test_turn (char *username, char *password, char *hostname, int port)
{
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);
  struct sockaddr_storage alternate_addr;
  socklen_t alternate_addrlen = sizeof (alternate_addr);
  struct sockaddr_storage relay_addr;
  socklen_t relay_addrlen = sizeof (relay_addr);
  ssize_t val;
  size_t len;
  int fd;
  uint8_t buf[STUN_MAX_MESSAGE_SIZE];
  uint8_t req[STUN_MAX_MESSAGE_SIZE];
  uint8_t refresh[STUN_MAX_MESSAGE_SIZE];
  size_t req_len;
  StunAgent agent;
  StunMessage msg;
  StunMessage req_msg;
  StunMessage refresh_msg;
  uint32_t bandwidth, lifetime;
  struct addrinfo hints, *res;
  int ret = -1;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;

  ret = getaddrinfo (hostname, port, &hints, &res);
  assert (ret == 0);

  stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS);

  /* Allocate a client socket and connect to server */
  fd = socket (AF_INET, SOCK_DGRAM, 0);
  assert (fd != -1);

  val = connect (fd,res->ai_addr, res->ai_addrlen);
#ifdef G_OS_WIN32
  assert (val == 0 || (WSAGetLastError () == WSAEINPROGRESS));
#else
  assert (val == 0 || (errno == EINPROGRESS));
#endif

  freeaddrinfo (res);


  /* Send old-style response */
  req_len = stun_usage_turn_create (&agent, &req_msg, req, sizeof(req),
      NULL,
      STUN_USAGE_TURN_REQUEST_PORT_NORMAL,
      -1, -1,
      username, strlen (username), password, strlen(password),
      STUN_USAGE_TURN_COMPATIBILITY_DRAFT9);
  assert (req_len > 0);

  val = send (fd, req, req_len, MSG_NOSIGNAL);
  assert (val >= 0);

  val = recv (fd, buf, 1000, 0);
  assert (val >= 0);

  assert (stun_agent_validate (&agent, &msg, buf, val, NULL, NULL)
      == STUN_VALIDATION_SUCCESS);

  val = stun_usage_turn_process (&msg,
      (struct sockaddr *)&relay_addr, &relay_addrlen,
      (struct sockaddr *)&addr, &addrlen,
      (struct sockaddr *)&alternate_addr, &alternate_addrlen,
      &bandwidth, &lifetime,
      STUN_USAGE_TURN_COMPATIBILITY_DRAFT9);
  assert (val == STUN_USAGE_TURN_RETURN_ERROR);

  req_len = stun_usage_turn_create (&agent, &req_msg, req, sizeof(req),
      &msg,
      STUN_USAGE_TURN_REQUEST_PORT_NORMAL,
      -1, -1,
      username, strlen (username), password, strlen(password),
      STUN_USAGE_TURN_COMPATIBILITY_DRAFT9);
  assert (req_len > 0);

  val = send (fd, req, req_len, MSG_NOSIGNAL);
  assert (val >= 0);

  val = recv (fd, buf, 1000, 0);
  assert (val >= 0);

  assert (stun_agent_validate (&agent, &msg, buf, val, NULL, NULL)
      == STUN_VALIDATION_SUCCESS);

  val = stun_usage_turn_process (&msg,
      (struct sockaddr *)&relay_addr, &relay_addrlen,
      (struct sockaddr *)&addr, &addrlen,
      (struct sockaddr *)&alternate_addr, &alternate_addrlen,
      &bandwidth, &lifetime,
      STUN_USAGE_TURN_COMPATIBILITY_DRAFT9);
  assert (val == STUN_USAGE_TURN_RETURN_MAPPED_SUCCESS);

  printaddr ("Relay address found : ", (struct sockaddr *)&relay_addr, relay_addrlen);
  printaddr ("Mapped address found : ",(struct sockaddr *) &addr, addrlen);


  req_len = stun_usage_turn_create_refresh (&agent, &refresh_msg, refresh,
      sizeof(refresh),  &req_msg, 0, username, strlen (username),
      password, strlen(password),STUN_USAGE_TURN_COMPATIBILITY_DRAFT9);
  assert (req_len > 0);

  val = send (fd, refresh, req_len, MSG_NOSIGNAL);
  assert (val >= 0);

  val = recv (fd, buf, 1000, 0);
  assert (val >= 0);

  assert (stun_agent_validate (&agent, &msg, buf, val, NULL, NULL)
      == STUN_VALIDATION_SUCCESS);

  val = close (fd);
  assert (val == 0);
}

static void turnserver (void)
{
  test_turn ("toto", "password", "127.0.0.1", "3478");
}

static void numb (void)
{
  test_turn ("youness.alaoui@collabora.co.uk", "badger", "numb.viagenie.ca", "3478");
}

static void test (void (*func) (void), const char *name)
{
  alarm (10);

  printf ("%s test... ", name);
  func ();
  puts ("OK");
}


int main (void)
{
  test (turnserver, "Testing TURN");
  test (numb, "Testing numb");
  return 0;
}
