
#include <string.h>

#include "random-glib.h"

int
main (void)
{
  NiceRNG *rng;
  gchar buf[9];

  buf[8] = '\0';

  nice_rng_set_new_func (nice_rng_glib_new_predictable);
  rng = nice_rng_new ();

  nice_rng_generate_bytes_print (rng, 8, buf);
  //g_debug ("%s", buf);
  g_assert (0 == strcmp (buf, "S9PObXR5"));

  nice_rng_generate_bytes (rng, 8, buf);
  g_assert (0 == strcmp (buf, "\x09\xd3\x15\xf2\x24\x57\x46\xd8"));

  nice_rng_free (rng);
  return 0;
}

