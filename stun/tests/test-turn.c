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
#include <sys/socket.h>
#include "stun/stunagent.h"
#include "stun/usages/turn.h"
#include "stun/usages/bind.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

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
static void responses (void)
{
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);
  ssize_t val;
  size_t len;
  int fd;
  int bind_fd;
  uint8_t buf[STUN_MAX_MESSAGE_SIZE];
  uint8_t req[STUN_MAX_MESSAGE_SIZE];
  size_t req_len;
  StunAgent agent;
  StunMessage msg;
  StunMessage req_msg;
  uint32_t bandwidth, lifetime;
  uint8_t username[] = {0x72, 0x63, 0x77, 0x45,
0x4f, 0x37, 0x39, 0x50,
0x75, 0x49, 0x59, 0x36,
0x32, 0x7a, 0x68, 0x7a};
#if 0
  uint8_t password[] = {0x1e, 0xbc, 0x9f, 0xa3,
0xf9, 0x61, 0x03, 0xa3,
0xfd, 0xdc, 0xee, 0xd7,
0xa6, 0xcf, 0x87, 0x4b};
#endif 
  uint8_t *password = NULL;
  struct addrinfo hints, *res;
  int ret = -1;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;

  ret = getaddrinfo ("216.239.51.126", "19295", &hints, &res);
  assert (ret == 0);

  stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC3489, 0);

  /* Allocate a client socket and connect to server */
  fd = socket (AF_INET, SOCK_DGRAM, 0);
  assert (fd != -1);
  bind_fd = socket (AF_INET, SOCK_DGRAM, 0);
  assert (bind_fd != -1);

  val = connect (fd,res->ai_addr, res->ai_addrlen);
  assert (val == 0 || (errno == EINPROGRESS));


  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;

  ret = getaddrinfo ("216.239.51.126", "19302", &hints, &res);
  assert (ret == 0);

  val = connect (bind_fd, res->ai_addr, res->ai_addrlen);
  assert (val == 0 || (errno == EINPROGRESS));

#if 0
  /* Send old-style response */
  req_len = stun_usage_bind_create (&agent, &req_msg, req, sizeof(req));
  assert (req_len > 0);

  val = send (bind_fd, req, req_len, MSG_NOSIGNAL);
  assert (val >= 0);

  val = recv (bind_fd, buf, 1000, 0);
  assert (val >= 0);

  assert (stun_agent_validate (&agent, &msg, buf, val, NULL, NULL)
      == STUN_VALIDATION_SUCCESS);

  sleep (3);
#endif

  /* Send old-style response */
  req_len = stun_usage_turn_create (&agent, &req_msg, req, sizeof(req),
      NULL,
      STUN_USAGE_TURN_REQUEST_PORT_NORMAL,
      0, 0,
      username, sizeof (username), password, sizeof(password),
      STUN_USAGE_TURN_COMPATIBILITY_GOOGLE);
  assert (req_len > 0);

  val = send (fd, req, req_len, MSG_NOSIGNAL);
  assert (val >= 0);

  val = recv (fd, buf, 1000, 0);
  assert (val >= 0);

  /* assert (stun_agent_validate (&agent, &msg, buf, val, NULL, NULL)
      == STUN_VALIDATION_SUCCESS);

  val = stun_usage_turn_process (&msg,
      (struct sockaddr *)&addr, &addrlen, (struct sockaddr *)&addr, &addrlen,
      &bandwidth, &lifetime);
      assert (val == STUN_USAGE_TURN_RETURN_SUCCESS);*/

  val = close (fd);
  assert (val == 0);
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
  test (responses, "Error responses");
  return 0;
}
