
#include "udp-bsd.h"

gint
main (void)
{
  NiceUDPSocketFactory man;
  NiceUDPSocket sock;
  NiceAddress addr = {0,};

  nice_udp_bsd_socket_factory_init (&man);
  addr.port = 9999;

  if (!man.init (&man, &sock, &addr))
    {
      g_debug ("failed to find to port 9999: server already running?");
      return 1;
    }

  for (;;)
    {
      gchar buf[1024];
      guint length;

      length = sock.recv (&sock, &addr, sizeof (buf), buf);
#ifdef DEBUG
      g_debug ("%s:%d", inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
#endif
      sock.send (&sock, &addr, length, buf);
    }

  return 0;
}

