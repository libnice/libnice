
#ifndef _AGENT_H
#define _AGENT_H

#include <arpa/inet.h>

#include <glib.h>

#include "udp.h"
#include "address.h"
#include "candidate.h"
#include "event.h"

G_BEGIN_DECLS

typedef struct _NiceAgent NiceAgent;

typedef void (*NiceAgentEventFunc) (
  NiceAgent *agent, NiceEvent *event);

struct _NiceAgent
{
  guint next_candidate_id;
  guint next_stream_id;
  NiceUDPSocketFactory *socket_factory;
  GSList *local_addresses;
  GSList *local_candidates;
  GSList *remote_candidates;
  GSList *streams;
  GSList *events;
};


typedef void (*NiceAgentRecvFunc) (
  NiceAgent *agent, guint stream_id, guint component_id, guint len,
  gchar *buf, gpointer user_data);


NiceAgent *
nice_agent_new (NiceUDPSocketFactory *factory);

NiceEvent *
nice_agent_pop_event (NiceAgent *agent);

void
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr);

guint
nice_agent_add_stream (
  NiceAgent *agent,
  NiceAgentRecvFunc recv_func,
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
  gchar *username,
  gchar *password);

void
nice_agent_recv (
  NiceAgent *agent,
  guint candidate_id);

GSList *
nice_agent_poll_read (
  NiceAgent *agent,
  GSList *other_fds);

const GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent);

G_END_DECLS

#endif /* _AGENT_H */

