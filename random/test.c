
#include <string.h>

#include "random-glib.h"

int
main (void)
{
  NiceRNG *rng;
  gchar buf[9];

  nice_rng_set_new_func (nice_rng_glib_new_predictable);
  rng = nice_rng_new ();
  nice_rng_generate_bytes_print (rng, 8, buf);
  buf[8] = '\0';
  //g_debug ("%s", buf);
  g_assert (0 == strcmp (buf, "S9PObXR5"));
  nice_rng_free (rng);
  return 0;
}

