
#include "udp-bsd.h"

gint
main (void)
{
  UDPSocketManager man;
  UDPSocket sock;
  struct sockaddr_in sin;

  udp_socket_manager_bsd_init (&man);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons (9999);

  if (!man.init (&man, &sock, &sin))
    {
      g_debug ("failed to find to port 9999: server already running?");
      return 1;
    }

  for (;;)
    {
      gchar buf[1024];
      guint length;

      length = sock.recv (&sock, &sin, sizeof (buf), buf);
#ifdef DEBUG
      g_debug ("%s:%d", inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
#endif
      sock.send (&sock, &sin, length, buf);
    }

  return 0;
}

