
#ifndef _EVENT_H
#define _EVENT_H

#include <glib.h>

G_BEGIN_DECLS

typedef enum _NiceEventType NiceEventType;

enum _NiceEventType
{
  EVENT_CANDIDATE_SELECTED,
};


typedef struct _NiceEvent NiceEvent;

struct _NiceEvent
{
  NiceEventType type;

  union {
    struct {
      NiceAddress *addr;
      guint candidate_id;
    } request_port;
    struct {
      NiceAddress *from;
      guint from_port;
      NiceAddress *to;
      guint to_port;
    } request_stun_query;
  };
};


NiceEvent *
_nice_event_new (NiceEventType type);

void
nice_event_free (NiceEvent *ev);

G_END_DECLS

#endif /* _EVENT_H */

