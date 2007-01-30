
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunAttribute *attr = stun_attribute_mapped_address_new (0x02030405, 2345);
  gchar *dump = stun_attribute_dump (attr);

  g_assert (NULL != dump);
  g_assert (0 == strcmp (dump, "MAPPED-ADDRESS 2.3.4.5:2345"));
  g_free (dump);
  stun_attribute_free (attr);
  return 0;
}

