
#include "stun.h"

int
main (void)
{
  StunMessage *msg;

  msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST, NULL, 1);

  g_assert (NULL ==
      stun_message_find_attribute (msg, STUN_ATTRIBUTE_MAPPED_ADDRESS));

  msg->attributes[0] = stun_attribute_mapped_address_new (0x01020304, 1234);

  g_assert (msg->attributes[0] ==
      stun_message_find_attribute (msg, STUN_ATTRIBUTE_MAPPED_ADDRESS));

  return 0;
}

