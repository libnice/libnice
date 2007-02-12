
#include <string.h>

#include "address.h"

static void
test_ipv4 (void)
{
  NiceAddress addr = {0,};
  NiceAddress other = {0,};
  gchar *str;

  nice_address_set_ipv4 (&addr, 0x01020304);
  g_assert (addr.type == NICE_ADDRESS_TYPE_IPV4);

  str = nice_address_to_string (&addr);
  g_assert (0 == strcmp (str, "1.2.3.4"));
  g_free (str);

  /* same address */
  nice_address_set_ipv4 (&other, 0x01020304);
  g_assert (TRUE == nice_address_equal (&addr, &other));

  /* different IP */
  nice_address_set_ipv4 (&other, 0x01020305);
  g_assert (FALSE == nice_address_equal (&addr, &other));

  /* different port */
  nice_address_set_ipv4 (&other, 0x01020304);
  addr.port = 1;
  g_assert (FALSE == nice_address_equal (&addr, &other));
}

static void
test_ipv6 (void)
{
  NiceAddress addr = {0,};
  gchar *str;

  nice_address_set_ipv6 (&addr,
      "\x00\x11\x22\x33"
      "\x44\x55\x66\x77"
      "\x88\x99\xaa\xbb"
      "\xcc\xdd\xee\xff");
  g_assert (addr.type == NICE_ADDRESS_TYPE_IPV6);

  str = nice_address_to_string (&addr);
  g_assert (0 == strcmp (str, "11:2233:4455:6677:8899:aabb:ccdd:eeff"));
  g_free (str);
}

int
main (void)
{
  test_ipv4 ();
  test_ipv6 ();
  return 0;
}

