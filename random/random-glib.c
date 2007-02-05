
#include "random-glib.h"

static void
rng_seed (NiceRNG *rng, guint32 seed)
{
  g_random_set_seed (seed);
}

static void
rng_generate_bytes (NiceRNG *rng, guint len, gchar *buf)
{
  guint i;

  for (i = 0; i < len; i++)
    buf[i] = g_random_int_range (0, 256);
}

static guint
rng_generate_int (NiceRNG *rng, guint low, guint high)
{
  return g_random_int_range (low, high);
}

static void
rng_free (NiceRNG *rng)
{
  g_slice_free (NiceRNG, rng);
}

NiceRNG *
nice_rng_glib_new (void)
{
  NiceRNG *ret;

  ret = g_slice_new0 (NiceRNG);
  ret->seed = rng_seed;
  ret->generate_bytes = rng_generate_bytes;
  ret->generate_int = rng_generate_int;
  ret->free = rng_free;
  return ret;
}

