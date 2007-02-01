
#include <string.h>
#include <stdio.h>

#include "udp-bsd.h"

gint
main (void)
{
  UDPSocketManager man;
  UDPSocket sock;
  struct sockaddr_in sin;

  udp_socket_manager_bsd_init (&man);

  if (!udp_socket_manager_alloc_socket (&man, &sock, NULL))
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

      udp_socket_send (&sock, &sin, strlen (buf), buf);
      length = udp_socket_recv (&sock, NULL, sizeof (buf), buf);
      g_print (buf);
    }

  udp_socket_close (&sock);
  udp_socket_manager_close (&man);
  return 0;
}

