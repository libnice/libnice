
#include <string.h>

#include "stun.h"

void
test_pack_mapped_address (void)
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
}

void
test_pack_username (void)
{
  StunAttribute *attr;
  gchar *packed;
  guint length;

  attr = stun_attribute_username_new ("abcdefghi");
  length = stun_attribute_pack (attr, &packed);

  // 4 bytes header + 9 bytes padded to 32 bits = 16
  g_assert (16 == length);
  // type
  g_assert (0 == memcmp (packed + 0, "\x00\x06", 2));
  // length
  g_assert (0 == memcmp (packed + 2, "\x00\x09", 2));
  // value
  g_assert (0 == memcmp (packed + 4, "abcdefghi\0\0\0", length - 4));

  g_free (packed);
  stun_attribute_free (attr);
}

int
main (void)
{
  test_pack_mapped_address ();
  test_pack_username ();
  return 0;
}

