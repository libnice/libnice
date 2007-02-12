
#ifndef _EVENT_H
#define _EVENT_H

#include <glib.h>

#include "candidate.h"

G_BEGIN_DECLS

typedef enum
{
  NICE_EVENT_COMPONENT_CONNECTED,
  NICE_EVENT_CANDIDATE_SELECTED,
} NiceEventType;


typedef struct _NiceEvent NiceEvent;

struct _NiceEvent
{
  NiceEventType type;

  union {
    struct {
      guint stream_id;
      guint component_id;
      NiceAddress addr;
    } component_connected;
    struct {
      NiceCandidate *local;
      NiceCandidate *remote;
    } candidate_selected;
  };
};


NiceEvent *
_nice_event_new (NiceEventType type);

void
nice_event_free (NiceEvent *ev);

G_END_DECLS

#endif /* _EVENT_H */

