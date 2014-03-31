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

#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <sys/socket.h>
#  include <netdb.h>
#endif

#include <sys/types.h>
#include "stun/stunagent.h"
#include "stun/usages/bind.h"

#include <unistd.h>
#include <getopt.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int ai_flags = 0;

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



static int run (int family, const char *hostname, const char *service)
{
  struct addrinfo hints, *res;
  const struct addrinfo *ptr;
  int ret = -1;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = ai_flags;
  if (service == NULL)
    service = "3478";

  ret = getaddrinfo (hostname, service, &hints, &res);
  if (ret)
  {
    fprintf (stderr, "%s (port %s): %s\n", hostname, service,
             gai_strerror (ret));
    return -1;
  }

  for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
  {
    union {
      struct sockaddr_storage storage;
      struct sockaddr addr;
    } addr;
    socklen_t addrlen = sizeof (addr);
    StunUsageBindReturn val;

    printaddr ("Server address", ptr->ai_addr, ptr->ai_addrlen);

    val = stun_usage_bind_run (ptr->ai_addr, ptr->ai_addrlen, &addr.storage,
        &addrlen);
    if (val)
      fprintf (stderr, "%d\n", val);
    else
    {
      printaddr ("Mapped address", &addr.addr, addrlen);
      ret = 0;
    }
  }

  freeaddrinfo (res);
  return ret;
}


int main (int argc, char *argv[])
{
  static const struct option opts[] =
  {
    { "ipv4",    no_argument, NULL, '4' },
    { "ipv6",    no_argument, NULL, '6' },
    { "help",    no_argument, NULL, 'h' },
    { "numeric", no_argument, NULL, 'n' },
    { "version", no_argument, NULL, 'V' },
    { NULL,      0,           NULL, 0   }
  };
  const char *server = NULL, *port = NULL;
  int family = AF_UNSPEC;

  for (;;)
  {
    int val = getopt_long (argc, argv, "46hnV", opts, NULL);
    if (val == EOF)
      break;

    switch (val)
    {
      case '4':
        family = AF_INET;
        break;

      case '6':
        family = AF_INET6;
        break;

      case 'h':
        printf ("Usage: %s [-4|-6] <server> [port number]\n"
                "Performs STUN Binding Discovery\n"
                "\n"
                "  -4, --ipv4    Force IP version 4\n"
                "  -6, --ipv6    Force IP version 6\n"
                "  -n, --numeric Server in numeric form\n"
            "\n", argv[0]);
        return 0;

      case 'n':
        ai_flags |= AI_NUMERICHOST;
        break;

      case 'V':
        printf ("stunbcd: STUN Binding Discovery client (%s v%s)\n",
                PACKAGE, VERSION);
        return 0;

      default:
        return 2;
    }
  }

  if (optind < argc)
    server = argv[optind++];
  if (optind < argc)
    port = argv[optind++];
  if (optind < argc)
  {
    fprintf (stderr, "%s: extra parameter `%s'\n", argv[0], argv[optind]);
    return 2;
  }

  return run (family, server, port) ? 1 : 0;
}
