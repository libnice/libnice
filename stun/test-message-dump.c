
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunMessage *msg;
  gchar *dump;

  msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST, NULL, 1);
  msg->attributes[0] = stun_attribute_mapped_address_new (0x02030405, 2345);

  dump = stun_message_dump (msg);
  g_assert (NULL != dump);
  g_assert (0 == strcmp (dump,
    "BINDING-REQUEST 00000000:00000000:00000000:00000000\n"
    "  MAPPED-ADDRESS 2.3.4.5:2345\n"));
  g_free (dump);
  stun_message_free (msg);
  return 0;
}

