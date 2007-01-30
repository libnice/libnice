
#include <string.h>

#include "stun.h"

int
main (void)
{
  gchar *dump;

  StunAttribute *attr = stun_attribute_unpack (4,
    "\x00\xff" // type
    "\x00\x00" // length
    );

  dump = stun_attribute_dump (attr);
  g_assert (0 == strcmp (dump, "UNKNOWN (255)"));
  g_free (dump);
  stun_attribute_free (attr);
  return 0;
}

