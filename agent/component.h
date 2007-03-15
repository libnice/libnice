
#ifndef _NICE_COMPONENT_H
#define _NICE_COMPONENT_H

#include <glib.h>

#include "agent.h"
#include "candidate.h"

G_BEGIN_DECLS

/* (ICE-13 §4.1.1) For RTP-based media streams, the RTP itself has a component
 * ID of 1, and RTCP a component ID of 2.  If an agent is using RTCP it MUST
 * obtain a candidate for it.  If an agent is using both RTP and RTCP, it
 * would end up with 2*K host candidates if an agent has K interfaces.
 */

typedef enum
{
  COMPONENT_TYPE_RTP,
  COMPONENT_TYPE_RTCP,
} ComponentType;


typedef struct _Component Component;

struct _Component
{
  ComponentType type;
  /* the local candidate that last received a valid connectivity check */
  NiceCandidate *active_candidate;
  /* the remote address that the last connectivity check came from */
  NiceAddress peer_addr;
  guint id;
  NiceComponentState state;
  GSList *local_candidates;
  GSList *remote_candidates;
  GSList *checks;
};

Component *
component_new (
  G_GNUC_UNUSED
  ComponentType type);

void
component_free (Component *cmp);

G_END_DECLS

#endif /* _NICE_COMPONENT_H */

