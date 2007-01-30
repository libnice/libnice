
#include "stun.h"

int
main (void)
{
  StunAttribute *attr;

  // attributes must be at least 4 bytes long
  attr = stun_attribute_unpack (0, NULL);
  g_assert (NULL == attr);

  attr = stun_attribute_unpack (8,
      "\x00\x01" // type = MAPPED-ADDRESS
      "\x00\x04" // length = 4 (invalid!)
      "\x00\x01" // padding, address family
      "\x09\x29" // port
      );
  g_assert (NULL == attr);
  return 0;
}

