
#include "random.h"
#include "random-glib.h"

NiceRNG *
nice_rng_new (void)
{
  NiceRNG *rng;

  rng = nice_glib_rng_new ();
  rng->seed (rng, 0);
  return rng;
}

void
nice_rng_generate_bytes (NiceRNG *rng, guint len, gchar *buf)
{
  rng->generate_bytes (rng, len, buf);
}

guint
nice_rng_generate_int (NiceRNG *rng, guint low, guint high)
{
  return rng->generate_int (rng, low, high);
}

void
nice_rng_generate_bytes_print (NiceRNG *rng, guint len, gchar *buf)
{
  guint i;
  gchar *chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "01234567890";

  for (i = 0; i < len; i++)
    buf[i] = chars[nice_rng_generate_int (rng, 0, 62)];
}

