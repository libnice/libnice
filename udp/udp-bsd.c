
/*
 * Implementation of UDP socket interface using Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */

#include <arpa/inet.h>

#include <unistd.h>

#include "udp-bsd.h"

/*** NiceUDPSocket ***/

static gint
socket_recv (
  NiceUDPSocket *sock,
  NiceAddress *from,
  guint len,
  gchar *buf)
{
  gint recvd;
  struct sockaddr_in sin = {0,};
  guint from_len = sizeof (sin);

  recvd = recvfrom (sock->fileno, buf, len, 0, (struct sockaddr *) &sin,
      &from_len);

  from->type = NICE_ADDRESS_TYPE_IPV4;
  from->addr_ipv4 = ntohl (sin.sin_addr.s_addr);
  from->port = ntohs (sin.sin_port);

  return recvd;
}

static gboolean
socket_send (
  NiceUDPSocket *sock,
  NiceAddress *to,
  guint len,
  const gchar *buf)
{
  struct sockaddr_in sin;

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (to->addr_ipv4);
  sin.sin_port = htons (to->port);

  sendto (sock->fileno, buf, len, 0, (struct sockaddr *) &sin, sizeof (sin));
  return TRUE;
}

static void
socket_close (NiceUDPSocket *sock)
{
  close (sock->fileno);
}

/*** NiceUDPSocketFactory ***/

static gboolean
socket_factory_init_socket (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  NiceAddress *addr)
{
  gint sockfd;
  struct sockaddr_in name = {0,};
  guint name_len = sizeof (name);

  sockfd = socket (PF_INET, SOCK_DGRAM, 0);

  if (sock < 0)
    return FALSE;

  name.sin_family = AF_INET;

  if (addr != NULL)
    {
      if (addr->addr_ipv4 != 0)
        name.sin_addr.s_addr = htonl (addr->addr_ipv4);
      else
        name.sin_addr.s_addr = INADDR_ANY;

      if (addr->port != 0)
        name.sin_port = htons (addr->port);
    }

  if (bind (sockfd, (struct sockaddr *) &name, sizeof (name)) != 0)
    {
      close (sockfd);
      return FALSE;
    }

  if (getsockname (sockfd, (struct sockaddr *) &name, &name_len) != 0)
    {
      close (sockfd);
      return FALSE;
    }

  if (name.sin_addr.s_addr == INADDR_ANY)
    sock->addr.addr_ipv4 = 0;
  else
    sock->addr.addr_ipv4 = ntohl (name.sin_addr.s_addr);

  sock->addr.port = ntohs (name.sin_port);

  sock->fileno = sockfd;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->close = socket_close;
  return TRUE;
}

static void
socket_factory_close (NiceUDPSocketFactory *man)
{
}

void
nice_udp_bsd_socket_factory_init (NiceUDPSocketFactory *man)
{
  man->init = socket_factory_init_socket;
  man->close = socket_factory_close;
}

