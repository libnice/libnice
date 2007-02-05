
#include "udp-bsd.h"

gint
main (void)
{
  NiceUDPSocketFactory factory;
  NiceUDPSocket sock;
  NiceAddress addr = {0,};

  nice_udp_bsd_socket_factory_init (&factory);
  addr.port = 9999;

  if (!nice_udp_socket_factory_make (&factory, &sock, &addr))
    {
      g_debug ("failed to bind to port 9999: server already running?");
      return 1;
    }

  for (;;)
    {
      gchar buf[1024];
      guint length;

      length = nice_udp_socket_recv (&sock, &addr, sizeof (buf), buf);
#ifdef DEBUG
        {
          gchar *ip;

          ip = nice_address_to_string (&addr);
          g_debug ("%s:%d", ip, addr.port);
          g_free (ip);
        }
#endif
      nice_udp_socket_send (&sock, &addr, length, buf);
    }

  return 0;
}

