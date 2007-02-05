
#include <string.h>

#include "udp.h"
#include "udp-fake.h"

int
main (void)
{
  NiceUDPSocketFactory man;
  NiceUDPSocket sock;
  NiceAddress addr = {0,};
  guint len;
  gchar buf[1024];

  nice_udp_fake_socket_factory_init (&man);

  memset (buf, '\0', 1024);

  /* create fake socket */

  if (!nice_udp_socket_factory_make (&man, &sock, &addr))
    g_assert_not_reached ();

  /* test recv */

  memcpy (buf, "he\0lo", 5);
  len = 5;
  addr.addr_ipv4 = 0x01020304;
  addr.port = 2345;
  nice_udp_fake_socket_push_recv (&sock, &addr, len, buf);

  memset (buf, '\0', 5);
  memset (&addr, '\0', sizeof (addr));

  len = nice_udp_socket_recv (&sock, &addr, sizeof (buf), buf);
  g_assert (len == 5);
  g_assert (memcmp (buf, "he\0lo", 5) == 0);
  g_assert (addr.addr_ipv4 == 0x01020304);
  g_assert (addr.port == 2345);

  /* test send */

  memcpy (buf, "la\0la", 5);
  len = 5;
  nice_udp_socket_send (&sock, &addr, len, buf);

  memset (buf, '\0', len);
  memset (&addr, '\0', sizeof (addr));

  len = nice_udp_fake_socket_pop_send (&sock, &addr, sizeof (buf), buf);
  g_assert (len == 5);
  g_assert (0 == memcmp (buf, "la\0la", 5));
  g_assert (addr.addr_ipv4 == 0x01020304);
  g_assert (addr.port == 2345);

  nice_udp_socket_close (&sock);
  nice_udp_socket_factory_close (&man);
  return 0;
}

