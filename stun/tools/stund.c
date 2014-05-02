/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007-2009 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
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

#ifdef __sun
#define _XPG4_2 1
#endif

#ifndef _WIN32

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/types.h>


#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include <unistd.h>
#include <errno.h>
#include <limits.h>

#ifndef SOL_IP
# define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif


#ifndef IPV6_RECVPKTINFO
# define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/** Default port for STUN binding discovery */
#define IPPORT_STUN  3478

#include "stun/stunagent.h"
#include "stund.h"

static const uint16_t known_attributes[] =  {
  0
};

/*
 * Creates a listening socket
 */
int listen_socket (int fam, int type, int proto, unsigned int port)
{
  int yes = 1;
  int fd = socket (fam, type, proto);
  union {
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr_storage storage;
  } addr;
  if (fd == -1)
  {
    perror ("Error opening IP port");
    return -1;
  }
  if (fd < 3)
    goto error;

  memset (&addr, 0, sizeof (addr));
  addr.storage.ss_family = fam;
#ifdef HAVE_SA_LEN
  addr.storage.ss_len = sizeof (addr);
#endif

  switch (fam)
  {
    case AF_INET:
      addr.in.sin_port = htons (port);
      break;

    case AF_INET6:
#ifdef IPV6_V6ONLY
      setsockopt (fd, SOL_IPV6, IPV6_V6ONLY, &yes, sizeof (yes));
#endif
      addr.in6.sin6_port = htons (port);
      break;

    default:
      assert (0);  /* should never be reached */
  }

  if (bind (fd, &addr.addr, sizeof (struct sockaddr)))
  {
    perror ("Error opening IP port");
    goto error;
  }

  if ((type == SOCK_DGRAM) || (type == SOCK_RAW))
  {
    switch (fam)
    {
      case AF_INET:
#ifdef IP_RECVERR
        setsockopt (fd, SOL_IP, IP_RECVERR, &yes, sizeof (yes));
#endif
        break;

      case AF_INET6:
#ifdef IPV6_RECVERR
        setsockopt (fd, SOL_IPV6, IPV6_RECVERR, &yes, sizeof (yes));
#endif
        break;

      default:
        assert (0);  /* should never be reached */
    }
  }
  else
  {
    if (listen (fd, INT_MAX))
    {
      perror ("Error opening IP port");
      goto error;
    }
  }

  return fd;

error:
  close (fd);
  return -1;
}

static int dgram_process (int sock, StunAgent *oldagent, StunAgent *newagent)
{
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } addr;
  socklen_t addr_len;
  uint8_t buf[STUN_MAX_MESSAGE_SIZE];
  size_t buf_len = 0;
  size_t len = 0;
  StunMessage request;
  StunMessage response;
  StunValidationStatus validation;
  StunAgent *agent = NULL;

  addr_len = sizeof (struct sockaddr_in);
  len = recvfrom (sock, buf, sizeof(buf), 0, &addr.addr, &addr_len);
  if (len == (size_t)-1)
    return -1;

  validation = stun_agent_validate (newagent, &request, buf, len, NULL, 0);

  if (validation == STUN_VALIDATION_SUCCESS) {
    agent = newagent;
  }
  else {
    validation = stun_agent_validate (oldagent, &request, buf, len, NULL, 0);
    agent = oldagent;
  }

  /* Unknown attributes */
  if (validation == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE)
  {
    buf_len = stun_agent_build_unknown_attributes_error (agent, &response, buf,
        sizeof (buf), &request);
    goto send_buf;
  }

  /* Mal-formatted packets */
  if (validation != STUN_VALIDATION_SUCCESS ||
      stun_message_get_class (&request) != STUN_REQUEST) {
    return -1;
  }

  switch (stun_message_get_method (&request))
  {
    case STUN_BINDING:
      stun_agent_init_response (agent, &response, buf, sizeof (buf), &request);
      if (stun_message_has_cookie (&request))
        stun_message_append_xor_addr (&response,
            STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr.storage, addr_len);
      else
         stun_message_append_addr (&response, STUN_ATTRIBUTE_MAPPED_ADDRESS,
             &addr.addr, addr_len);
      break;

    case STUN_SHARED_SECRET:
    case STUN_ALLOCATE:
    case STUN_SEND:
    case STUN_CONNECT:
    case STUN_IND_SEND:
    case STUN_IND_DATA:
    case STUN_CREATEPERMISSION:
    case STUN_CHANNELBIND:
    default:
      if (!stun_agent_init_error (agent, &response, buf, sizeof (buf),
              &request, STUN_ERROR_BAD_REQUEST))
        return -1;
  }

  buf_len = stun_agent_finish_message (agent, &response, NULL, 0);
send_buf:
  len = sendto (sock, buf, buf_len, 0, &addr.addr, addr_len);
  return (len < buf_len) ? -1 : 0;
}


static int run (int family, int protocol, unsigned port)
{
  StunAgent oldagent;
  StunAgent newagent;
  int sock = listen_socket (family, SOCK_DGRAM, protocol, port);
  if (sock == -1)
    return -1;

  stun_agent_init (&oldagent, known_attributes,
      STUN_COMPATIBILITY_RFC3489, 0);
  stun_agent_init (&newagent, known_attributes,
      STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_USE_FINGERPRINT);

  for (;;)
    dgram_process (sock, &oldagent, &newagent);
}


/* Pretty useless dummy signal handler...
 * But calling exit() is needed for gcov to work properly. */
static void exit_handler (int signum)
{
  (void)signum;
  exit (0);
}


int main (int argc, char *argv[])
{
  int family = AF_INET;
  unsigned port = IPPORT_STUN;

  for (;;)
  {
    int c = getopt (argc, argv, "46");
    if (c == EOF)
      break;

    switch (c)
    {
      default:
      case '4':
        family = AF_INET;
        break;

      case '6':
        family = AF_INET6;
        break;
    }
  }

  if (optind < argc)
    port = atoi (argv[optind++]);

  signal (SIGINT, exit_handler);
  signal (SIGTERM, exit_handler);
  return run (family, IPPROTO_UDP, port) ? EXIT_FAILURE : EXIT_SUCCESS;
}

#else
int main (int argc, char **argv) {
  return 0;
}
#endif
