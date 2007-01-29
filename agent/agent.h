
#ifndef _AGENT_H
#define _AGENT_H


#include "address.h"


typedef enum media_type MediaType;

enum media_type
{
  MEDIA_TYPE_AUDIO,
  MEDIA_TYPE_VIDEO,
};


/*** candidate ***/

typedef enum candidate_type CandidateType;

enum candidate_type
{
  CANDIDATE_TYPE_HOST,
  CANDIDATE_TYPE_SERVER_REFLEXIVE,
  CANDIDATE_TYPE_PEER_REFLEXIVE,
  CANDIDATE_TYPE_RELAYED,
};


typedef struct _candidate Candidate;

struct _candidate
{
  CandidateType type;
  guint id;
  Address addr;
  Address base_addr;
  guint16 port;
  guint32 priority;
  guint stream_id;
  guint component_id;
  // guint generation;
  // gchar *foundation;
  UDPSocket sock;
};


Candidate *
candidate_new (CandidateType type);
void
candidate_free (Candidate *candidate);
gfloat
candidate_jingle_priority (Candidate *candidate);
guint32
candidate_ice_priority (Candidate *candidate);


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
      Address *addr;
      guint candidate_id;
    } request_port;
    struct {
      Address *from;
      guint from_port;
      Address *to;
      guint to_port;
    } request_stun_query;
  };
};


void
event_free (Event *ev);


/*** agent ***/


typedef struct _agent Agent;

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


typedef void (*AgentRecvHandler) (
  Agent *agent, guint stream_id, guint component_id, guint len, gchar *buf);


Agent *
ice_agent_new (UDPSocketManager *mgr);
Event *
ice_agent_pop_event (Agent *agent);
void
ice_agent_add_local_address (Agent *agent, Address *addr);
guint
ice_agent_add_stream (
  Agent *agent,
  MediaType type,
  AgentRecvHandler handle_recv);
void
ice_agent_free (Agent *agent);
void
ice_agent_add_remote_candidate (
  Agent *agent,
  CandidateType type,
  Address *addr,
  guint port);
void
ice_agent_recv (
  Agent *agent,
  guint candidate_id);

#endif /* _AGENT_H */

