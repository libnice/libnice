
#ifndef _AGENT_H
#define _AGENT_H

typedef enum media_type MediaType;

enum media_type
{
  MEDIA_TYPE_AUDIO,
  MEDIA_TYPE_VIDEO,
};


/*** address ***/


typedef struct _address Address;


Address *
address_new_ipv4_from_string (gchar *str);
gboolean
address_equal (Address *a, Address *b);
void
address_free (Address *addr);


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
  Address *addr;
  Address *base_addr;
  // guint sock;
  guint16 port;
  guint32 priority;
  // Stream *stream;
  // guint component_id;
  // guint generation;
  // gchar *foundation;
};


/*** event ***/


typedef enum event_type EventType;

enum event_type
{
  EVENT_REQUEST_PORT,
  EVENT_LOCAL_CANDIDATES_READY,
  EVENT_REQUEST_STUN_QUERY,
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
  GSList *local_addresses;
  GSList *local_candidates;
  GSList *remote_candidates;
  GSList *streams;
  GSList *events;
};


Agent *
ice_agent_new ();
Event *
ice_agent_pop_event (Agent *agent);
void
ice_agent_add_local_address (Agent *agent, Address *addr);
void
ice_agent_add_stream (Agent *agent, MediaType type);
void
ice_agent_set_candidate_port (Agent *agent, guint candidate_id, guint port);
void
ice_agent_free (Agent *agent);
void
ice_agent_add_remote_candidate (
  Agent *agent,
  CandidateType type,
  Address *addr,
  guint port);

#endif /* _AGENT_H */

