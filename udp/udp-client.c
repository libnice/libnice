
#include <string.h>
#include <stdio.h>

#include "udp-bsd.h"

gint
main (void)
{
  NiceUDPSocketFactory man;
  NiceUDPSocket sock;
  struct sockaddr_in sin;

  nice_udp_bsd_socket_factory_init (&man);

  if (!nice_udp_socket_factory_make (&man, &sock, NULL))
    g_assert_not_reached ();

  if (inet_pton (AF_INET, "127.0.0.1", &(sin.sin_addr)) < 0)
    g_assert_not_reached ();

  sin.sin_family = AF_INET;
  sin.sin_port = htons (9999);

  for (;;)
    {
      gchar buf[1024];
      guint length;

      if (fgets (buf, sizeof (buf), stdin) == NULL)
        break;

      nice_udp_socket_send (&sock, &sin, strlen (buf), buf);
      length = nice_udp_socket_recv (&sock, NULL, sizeof (buf), buf);
      g_print (buf);
    }

  nice_udp_socket_close (&sock);
  nice_udp_socket_factory_close (&man);
  return 0;
}

