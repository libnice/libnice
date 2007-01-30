
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunMessage *msg = stun_message_binding_request_new ();
  gchar *dump;

  msg->attributes = g_malloc0 (2 * sizeof (StunAttribute *));
  msg->attributes[0] = stun_attribute_mapped_address_new (0x02030405, 2345);

  dump = stun_message_dump (msg);
  g_assert (NULL != dump);
  g_assert (0 == strcmp (dump,
    "BINDING-REQUEST 00000000:00000000:00000000:00000000\n"
    "  MAPPED-ADDRESS 2.3.4.5:2345"));
  g_free (dump);
  stun_message_free (msg);
  return 0;
}

