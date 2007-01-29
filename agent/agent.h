
#ifndef _AGENT_H
#define _AGENT_H

#include <arpa/inet.h>

#include <glib.h>

#include "udp.h"
#include "address.h"
#include "candidate.h"


/*** event ***/


typedef enum event_type EventType;

enum event_type
{
  EVENT_CANDIDATE_SELECTED,
};


typedef struct _event Event;

struct _event
{
  EventType type;

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


void
event_free (Event *ev);


/*** agent ***/


typedef struct _agent NiceAgent;

struct _agent
{
  guint next_candidate_id;
  guint next_stream_id;
  UDPSocketManager *sockmgr;
  GSList *local_addresses;
  GSList *local_candidates;
  GSList *remote_candidates;
  GSList *streams;
  GSList *events;
};


typedef void (*NiceAgentRecvHandler) (
  NiceAgent *agent, guint stream_id, guint component_id, guint len,
  gchar *buf, gpointer user_data);


NiceAgent *
nice_agent_new (UDPSocketManager *mgr);
Event *
nice_agent_pop_event (NiceAgent *agent);
void
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr);
guint
nice_agent_add_stream (
  NiceAgent *agent,
  NiceAgentRecvHandler handle_recv,
  gpointer handle_recv_data);
void
nice_agent_free (NiceAgent *agent);
void
nice_agent_add_remote_candidate (
  NiceAgent *agent,
  NiceCandidateType type,
  NiceAddress *addr,
  guint port);
void
nice_agent_recv (
  NiceAgent *agent,
  guint candidate_id);
const GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent);

#endif /* _AGENT_H */

