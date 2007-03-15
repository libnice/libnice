
#ifndef _NICE_STREAM_H
#define _NICE_STREAM_H

#include <glib.h>

#include "component.h"

G_BEGIN_DECLS

typedef struct _Stream Stream;

struct _Stream
{
  guint id;
  /* XXX: streams can have multiple components */
  Component *component;
};

Stream *
stream_new (void);

void
stream_free (Stream *stream);

G_END_DECLS

#endif /* _NICE_STREAM_H */

