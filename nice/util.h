
#ifndef _UTIL_H
#define _UTIL_H

#include <glib.h>

#include "agent.h"

G_BEGIN_DECLS

NiceCandidate *
nice_candidate_from_string (const gchar *s);
gchar *
nice_candidate_to_string (NiceCandidate *candidate);

G_END_DECLS

#endif /* _UTIL_H */

