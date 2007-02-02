
#include <string.h>

#include "stun.h"

int
main (void)
{
  StunMessage *msg;
  gchar *dump;

  msg = stun_message_new (0xffff, NULL, 0);
  dump = stun_message_dump (msg);
  g_assert (0 == strcmp (dump,
        "(UNKNOWN) 00000000:00000000:00000000:00000000\n"));
  stun_message_free (msg);

  return 0;
}

