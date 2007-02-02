
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunMessage *msg;
  gchar *dump;

  msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 1);
  msg->attributes[0] = stun_attribute_mapped_address_new (0x02030405, 2345);

  dump = stun_message_dump (msg);
  g_assert (NULL != dump);
  g_assert (0 == strcmp (dump,
    "BINDING-REQUEST 00010203:04050607:08090a0b:0c0d0e0f\n"
    "  MAPPED-ADDRESS 2.3.4.5:2345\n"));
  g_free (dump);
  stun_message_free (msg);
  return 0;
}

