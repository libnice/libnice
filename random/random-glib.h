
#ifndef _RANDOM_GLIB_H
#define _RANDOM_GLIB_H

#include <glib.h>

#include "random.h"

G_BEGIN_DECLS

NiceRNG *
nice_rng_glib_new (void);

NiceRNG *
nice_rng_glib_new_predictable (void);

G_END_DECLS

#endif /* _RANDOM_GLIB_H */

