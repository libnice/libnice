
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunMessage *msg = stun_message_binding_request_new ();
  gchar *packed;
  guint length;

  memcpy (msg->transaction_id,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
  msg->attributes = g_malloc0 (2 * sizeof (StunAttribute *));
  msg->attributes[0] = stun_attribute_mapped_address_new (0x02030405, 2345);
  length = stun_message_pack (msg, &packed);

  g_assert (packed != NULL);
  g_assert (length == 32);
  g_assert (0 == memcmp (packed + 0, "\x00\x01", 2));
  g_assert (0 == memcmp (packed + 2, "\x00\x0c", 2));
  g_assert (0 == memcmp (packed + 4,
    "\x00\x01\x02\x03"
    "\x04\x05\x06\x07"
    "\x08\x09\x0a\x0b"
    "\x0c\x0d\x0e\x0f", 16));
  g_assert (0 == memcmp (packed + 20,
    "\x00\x01"          // type
    "\x00\x08"          // length
    "\x00\x01"          // padding, address family
    "\x09\x29"          // port
    "\x02\x03\x04\x05", // IP address
    12));

  g_free (packed);
  stun_message_free (msg);
  return 0;
}

