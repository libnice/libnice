
#ifndef _AGENT_H
#define _AGENT_H

#include <glib.h>

#include "udp.h"
#include "address.h"
#include "candidate.h"
#include "event.h"

G_BEGIN_DECLS

typedef struct _NiceAgent NiceAgent;

typedef void (*NiceAgentEventFunc) (
  NiceAgent *agent, NiceEvent *event);

typedef void (*NiceAgentRecvFunc) (
  NiceAgent *agent, guint stream_id, guint component_id, guint len,
  gchar *buf, gpointer user_data);

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
  gboolean main_context_set;
  GMainContext *main_context;
  NiceAgentRecvFunc read_func;
  gpointer read_func_data;
};

NiceAgent *
nice_agent_new (NiceUDPSocketFactory *factory);

void
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr);

guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components);

void
nice_agent_remove_stream (
  NiceAgent *agent,
  guint stream_id);

void
nice_agent_free (NiceAgent *agent);

void
nice_agent_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  NiceAddress *addr,
  const gchar *username,
  const gchar *password);

guint
nice_agent_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint buf_len,
  gchar *buf);

GSList *
nice_agent_poll_read (
  NiceAgent *agent,
  GSList *other_fds,
  NiceAgentRecvFunc func,
  gpointer data);

void
nice_agent_send (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  const gchar *buf);

const GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent);

gboolean
nice_agent_main_context_attach (
  NiceAgent *agent,
  GMainContext *ctx,
  NiceAgentRecvFunc func,
  gpointer data);

G_END_DECLS

#endif /* _AGENT_H */

