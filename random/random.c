
#include "random.h"
#include "random-glib.h"

static NiceRNG * (*nice_rng_new_func) (void) = NULL;

NiceRNG *
nice_rng_new (void)
{
  if (nice_rng_new_func == NULL)
    return nice_rng_glib_new ();
  else
    return nice_rng_new_func ();
}

void
nice_rng_set_new_func (NiceRNG * (*func) (void))
{
  nice_rng_new_func = func;
}

void
nice_rng_free (NiceRNG *rng)
{
  rng->free (rng);
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
  const gchar *chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "01234567890";

  for (i = 0; i < len; i++)
    buf[i] = chars[nice_rng_generate_int (rng, 0, 62)];
}

