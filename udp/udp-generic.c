
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

gboolean
udp_socket_manager_alloc_socket (
  UDPSocketManager *man,
  UDPSocket *sock,
  struct sockaddr_in *sin)
{
  return man->init (man, sock, sin);
}

void
udp_socket_manager_close (UDPSocketManager *man)
{
  man->close (man);
}

guint
udp_socket_recv (
  UDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf)
{
  return sock->recv (sock, sin, len, buf);
}

void
udp_socket_send (
  UDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf)
{
  sock->send (sock, sin, len, buf);
}

void
udp_socket_close (UDPSocket *sock)
{
  sock->close (sock);
}

