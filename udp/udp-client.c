
#include <string.h>
#include <stdio.h>

#include "udp-bsd.h"

gint
main (void)
{
  NiceUDPSocketFactory man;
  NiceUDPSocket sock;
  NiceAddress addr;

  nice_udp_bsd_socket_factory_init (&man);

  if (!nice_udp_socket_factory_make (&man, &sock, NULL))
    g_assert_not_reached ();

  if (!nice_address_set_ipv4_from_string (&addr, "127.0.0.1"))
    g_assert_not_reached ();

  addr.port = 9999;

  for (;;)
    {
      gchar buf[1024];
      guint length;

      if (fgets (buf, sizeof (buf), stdin) == NULL)
        break;

      nice_udp_socket_send (&sock, &addr, strlen (buf), buf);
      length = nice_udp_socket_recv (&sock, &addr, sizeof (buf), buf);
      g_print (buf);
    }

  nice_udp_socket_close (&sock);
  nice_udp_socket_factory_close (&man);
  return 0;
}

