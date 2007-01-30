
#include "stun.h"

int
main (void)
{
  /* can't create an unknown attribute directly, so create a MAPPED-ADDRESS
   * and change its type
   */
  StunAttribute *attr = stun_attribute_mapped_address_new (0x02030405, 2345);
  gchar *packed = NULL;
  guint length;

  attr->type = 0xff;
  length = stun_attribute_pack (attr, &packed);
  g_assert (0 == length);
  g_assert (NULL == packed);

  stun_attribute_free (attr);
  return 0;
}

