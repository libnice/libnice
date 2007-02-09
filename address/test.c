
#include <string.h>

#include "address.h"

int
main (void)
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

  return 0;
}

