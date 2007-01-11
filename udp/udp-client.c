
#include <string.h>
#include <stdio.h>

#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

gint
main (void)
{
  struct UDPSocketManager man;
  struct UDPSocket sock;
  struct sockaddr_in sin;

  udp_socket_manager_init (&man);

  if (!man.init (&man, &sock, NULL))
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

      sock.send (&sock, &sin, strlen (buf), buf);
      length = sock.recv (&sock, NULL, sizeof (buf), buf);
      g_print (buf);
    }

  sock.close (&sock);
  return 0;
}

