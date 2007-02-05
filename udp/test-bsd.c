
#include <string.h>

#include "udp-bsd.h"

int
main (void)
{
  NiceUDPSocketFactory factory;
  NiceUDPSocket server;
  NiceUDPSocket client;
  NiceAddress tmp = {0,};
  gchar buf[5];

  nice_udp_bsd_socket_factory_init (&factory);

  g_assert (nice_udp_socket_factory_make (&factory, &server, NULL));
  // not bound to a particular interface
  g_assert (server.addr.addr_ipv4 == 0);
  // is bound to a particular port
  g_assert (server.addr.port != 0);

  g_assert (nice_udp_socket_factory_make (&factory, &client, NULL));
  // not bound to a particular interface
  g_assert (client.addr.addr_ipv4 == 0);
  // is bound to a particular port
  g_assert (client.addr.port != 0);

  nice_udp_socket_send (&client, &server.addr, 5, "hello");
  g_assert (5 == nice_udp_socket_recv (&server, &tmp, 5, buf));
  g_assert (0 == strncmp (buf, "hello", 5));
  g_assert (tmp.port == client.addr.port);

  nice_udp_socket_send (&server, &client.addr, 5, "uryyb");
  g_assert (5 == nice_udp_socket_recv (&client, &tmp, 5, buf));
  g_assert (0 == strncmp (buf, "uryyb", 5));
  g_assert (tmp.port == server.addr.port);

  nice_udp_socket_close (&client);
  nice_udp_socket_close (&server);
  nice_udp_socket_factory_close (&factory);
  return 0;
}

