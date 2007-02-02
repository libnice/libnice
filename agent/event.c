
#include "address.h"
#include "event.h"

NiceEvent *
_nice_event_new (NiceEventType type)
{
  NiceEvent *ev;

  ev = g_slice_new0 (NiceEvent);
  ev->type = type;
  return ev;
}


void
nice_event_free (NiceEvent *ev)
{
  switch (ev->type)
    {
      case EVENT_CANDIDATE_SELECTED:
        break;
    }

  g_slice_free (NiceEvent, ev);
}

