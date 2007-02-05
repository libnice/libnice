
#ifndef _RANDOM_H
#define _RANDOM_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct _NiceRNG NiceRNG;

struct _NiceRNG {
  void (*seed) (NiceRNG *src, guint32 seed);
  void (*generate_bytes) (NiceRNG *src, guint len, gchar *buf);
  guint (*generate_int) (NiceRNG *src, guint low, guint high);
  void (*free) (NiceRNG *src);
  gpointer priv;
};

NiceRNG *
nice_rng_new (void);

void
nice_rng_set_new_func (NiceRNG * (*func) (void));

void
nice_rng_seed (NiceRNG *rng, guint32 seed);

void
nice_rng_generate_bytes (NiceRNG *rng, guint len, gchar *buf);

void
nice_rng_generate_bytes_print (NiceRNG *rng, guint len, gchar *buf);

guint
nice_rng_generate_int (NiceRNG *rng, guint low, guint high);

void
nice_rng_free (NiceRNG *rng);

G_END_DECLS

#endif // _RANDOM_H

