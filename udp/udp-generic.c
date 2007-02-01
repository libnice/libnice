
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

gboolean
nice_udp_socket_factory_make (
  NiceUDPSocketFactory *man,
  NiceUDPSocket *sock,
  struct sockaddr_in *sin)
{
  return man->init (man, sock, sin);
}

void
nice_udp_socket_factory_close (NiceUDPSocketFactory *man)
{
  man->close (man);
}

guint
nice_udp_socket_recv (
  NiceUDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf)
{
  return sock->recv (sock, sin, len, buf);
}

void
nice_udp_socket_send (
  NiceUDPSocket *sock,
  struct sockaddr_in *sin,
  guint len,
  gchar *buf)
{
  sock->send (sock, sin, len, buf);
}

void
nice_udp_socket_close (NiceUDPSocket *sock)
{
  sock->close (sock);
}

