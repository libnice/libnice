
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunAttribute *attr;

  attr = stun_attribute_unpack (12,
    "\x00\x01"         // type
    "\x00\x08"         // length
    "\x00\x01"         // padding, address family
    "\x09\x29"         // port
    "\x02\x03\x04\x05" // IP address
    );

  g_assert (NULL != attr);
  g_assert (attr->type == STUN_ATTRIBUTE_MAPPED_ADDRESS);
  // length is not used
  g_assert (attr->length == 0);
  g_assert (attr->address.af == 1);
  g_assert (attr->address.port == 2345);
  g_assert (attr->address.ip == 0x02030405);
  stun_attribute_free (attr);

  attr = stun_attribute_unpack (9,
      "\x00\x06" // type
      "\x00\x05" // length
      "abcde"    // value
      );

  g_assert (NULL != attr);
  g_assert (attr->length == 5);
  g_assert (attr->type == STUN_ATTRIBUTE_USERNAME);
  g_assert (0 == memcmp (attr->username, "abcde", 5));
  stun_attribute_free (attr);

  attr = stun_attribute_unpack (10,
      "\x00\x07" // type
      "\x00\x06" // length
      "fghijk"   // value
      );

  g_assert (NULL != attr);
  g_assert (attr->length == 6);
  g_assert (attr->type == STUN_ATTRIBUTE_PASSWORD);
  g_assert (0 == memcmp (attr->password, "fghijk", 6));
  stun_attribute_free (attr);

  return 0;
}

