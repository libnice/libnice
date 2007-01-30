
#include "stun.h"

int
main (void)
{
  StunAttribute *attr = stun_attribute_unpack (8,
      "\x00\xff" // type
      "\x00\x04" // length
      "\xff\xff" // some data
      "\xff\xff"
      );

  g_assert (NULL != attr);
  g_assert (attr->type == 0xff);
  stun_attribute_free (attr);
  return 0;
}

