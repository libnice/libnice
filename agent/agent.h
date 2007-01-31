
#ifndef _AGENT_H
#define _AGENT_H

#include <arpa/inet.h>

#include <glib.h>

#include "udp.h"
#include "address.h"
#include "candidate.h"

G_BEGIN_DECLS

/*** event ***/


typedef enum event_type EventType;

enum event_type
{
  EVENT_CANDIDATE_SELECTED,
};


typedef struct _Event Event;

struct _Event
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


typedef struct _NiceAgent NiceAgent;

struct _NiceAgent
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
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  NiceAddress *addr,
  guint port,
  gchar *username,
  gchar *password);

void
nice_agent_recv (
  NiceAgent *agent,
  guint candidate_id);

const GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent);

G_END_DECLS

#endif /* _AGENT_H */

