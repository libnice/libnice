
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunAttribute *attr = stun_attribute_mapped_address_new (0x02030405, 2345);
  gchar *packed;
  guint length;

  length = stun_attribute_pack (attr, &packed);

  g_assert (12 == length);
  g_assert (NULL != packed);

  g_assert (0 == memcmp (packed,
    "\x00\x01"          // type
    "\x00\x08"          // length
    "\x00\x01"          // padding, address family
    "\x09\x29"          // port
    "\x02\x03\x04\x05", // IP address
    length));
  g_free (packed);
  stun_attribute_free (attr);
  return 0;
}

