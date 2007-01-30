
#include "stun.h"

int
main (void)
{
  StunMessage *msg = stun_message_unpack (32,
    "\x00\x01"         // type
    "\x00\x0c"         // length
    "\x00\x01\x02\x03" // transaction ID
    "\x04\x05\x06\x07"
    "\x08\x09\x0a\x0b"
    "\x0c\x0d\x0e\x0f"
    "\x00\x01"         // attr1 type
    "\x00\x08"         // attr1 length
    "\x00\x01"         // padding, address family
    "\x09\x29"         // port
    "\x02\x03\x04\x05" // IP address
    );

  g_assert (msg->type == STUN_MESSAGE_BINDING_REQUEST);
  g_assert (msg->attributes[0] != NULL);
  g_assert (msg->attributes[0]->type == STUN_ATTRIBUTE_MAPPED_ADDRESS);
  g_assert (msg->attributes[0]->address.port == 2345);
  g_assert (msg->attributes[0]->address.ip == 0x02030405);
  g_assert (msg->attributes[1] == NULL);
  stun_message_free (msg);
  return 0;
}

