
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include <stun.h>
#include <udp.h>

#include <agent.h>

/*** component ***/


/* (ICE12 §5.1) For RTP-based media streams, the RTP itself has a component ID
 * of 1, and RTCP a component ID of 2.  If an agent is using RTCP it MUST
 * obtain a candidate for it.  If an agent is using both RTP and RTCP, it
 * would end up with 2*K host candidates if an agent has K interfaces.
 */

typedef enum component_type ComponentType;

enum component_type
{
  COMPONENT_TYPE_RTP,
  COMPONENT_TYPE_RTCP,
};


typedef struct _component Component;

struct _component
{
  ComponentType type;
  guint id;
};


static Component *
component_new (ComponentType type)
{
  Component *component;

  component = g_slice_new0 (Component);
  component->id = 1;
  return component;
}


static void
component_free (Component *cmp)
{
  g_slice_free (Component, cmp);
}


/*** stream ***/


typedef struct _stream Stream;

struct _stream
{
  guint id;
  /* XXX: streams can have multiple components */
  Component *component;
  AgentRecvHandler handle_recv;
};


static Stream *
stream_new ()
{
  Stream *stream;

  stream = g_slice_new0 (Stream);
  stream->component = component_new (COMPONENT_TYPE_RTP);
  return stream;
}


static void
stream_free (Stream *stream)
{
  component_free (stream->component);
  g_slice_free (Stream, stream);
}


/*** candidate_pair ***/


typedef struct _candidate_pair CandidatePair;

struct _candidate_pair
{
  Candidate local;
  Candidate remote;
};


typedef enum check_state CheckState;

/* ICE12 §6.7 (p24) */
enum check_state
{
  CHECK_STATE_WAITING,
  CHECK_STATE_IN_PROGRESS,
  CHECK_STATE_SUCCEEDED,
  CHECK_STATE_FAILED,
  CHECK_STATE_FROZEN,
};


typedef enum check_list_state CheckListState;

enum check_list_state
{
  CHECK_LIST_STATE_RUNNING,
  CHECK_LIST_STATE_COMPLETED,
};


/* ICE12 §6.7 */
guint64
candidate_pair_priority (
      guint64 offerer_prio,
      guint64 answerer_prio)
{
  return (
      0x100000000LL * MIN (offerer_prio, answerer_prio) +
      2 * MAX (offerer_prio, answerer_prio) +
      (offerer_prio > answerer_prio ? 1 : 0));
}


/*** event ***/


#if 0
static Event *
event_new (EventType type)
{
  Event *ev;

  ev = g_slice_new0 (Event);
  ev->type = type;
  return ev;
}
#endif


void
event_free (Event *ev)
{
  switch (ev->type)
    {
      case EVENT_CANDIDATE_SELECTED:
        break;
    }

  g_slice_free (Event, ev);
}


/*** agent ***/


Agent *
ice_agent_new (UDPSocketManager *mgr)
{
  Agent *agent;

  agent = g_slice_new0 (Agent);
  agent->sockmgr = mgr;
  agent->next_candidate_id = 1;
  agent->next_stream_id = 1;
  return agent;
}


Event *
ice_agent_pop_event (Agent *agent)
{
  Event *event;
  GSList *head;

  if (agent->events == NULL)
    return NULL;

  head = agent->events;
  event = (Event *) head->data;
  agent->events = head->next;
  g_slist_free_1 (head);
  return event;
}


void
ice_agent_push_event (Agent *agent, Event *ev)
{
  agent->events = g_slist_append (agent->events, ev);
}


static void
ice_agent_add_local_host_candidate (
  Agent *agent,
  guint stream_id,
  guint component_id,
  Address *address)
{
  Candidate *candidate;
  struct sockaddr_in sin;

  candidate = candidate_new (CANDIDATE_TYPE_HOST);
  candidate->id = agent->next_candidate_id++;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = *address;
  agent->local_candidates = g_slist_append (agent->local_candidates,
      candidate);

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl (address->addr_ipv4);
  sin.sin_port = 0;
  /* XXX: handle error */
  udp_socket_manager_alloc_socket (agent->sockmgr, &(candidate->sock), &sin);
  candidate->port = ntohs (candidate->sock.addr.sin_port);
}


guint
ice_agent_add_stream (
  Agent *agent,
  AgentRecvHandler handle_recv)
{
  Stream *stream;
  GSList *i;

  stream = stream_new ();
  stream->id = agent->next_stream_id++;
  stream->handle_recv = handle_recv;
  agent->streams = g_slist_append (agent->streams, stream);

  /* generate a local host candidate for each local address */

  for (i = agent->local_addresses; i; i = i->next)
    {
      Address *addr = (Address *) i->data;

      ice_agent_add_local_host_candidate (agent, stream->id,
          stream->component->id, addr);

      /* XXX: need to check for redundant candidates? */
      /* later: send STUN requests to obtain server-reflexive candidates */
    }

  return stream->id;
}


void
ice_agent_add_local_address (Agent *agent, Address *addr)
{
  agent->local_addresses = g_slist_append (agent->local_addresses,
      address_dup (addr));

  /* XXX: Should we generate local candidates for existing streams at this
   * point, or require that local addresses are set before media streams are
   * added?
   */
}


void
ice_agent_add_remote_candidate (
  Agent *agent,
  CandidateType type,
  Address *addr,
  guint port)
{
  /* append to agent->remote_candidates */

  Candidate *candidate;

  candidate = candidate_new (type);
  /* do remote candidates need IDs? */
  candidate->id = 0;
  candidate->addr = *addr;
  candidate->port = port;

  agent->remote_candidates = g_slist_append (agent->remote_candidates,
      candidate);

  /* later: for each component, generate a new check with the new candidate */
}


static Candidate *
_local_candidate_lookup (Agent *agent, guint candidate_id)
{
  GSList *i;

  for (i = agent->local_candidates; i; i = i->next)
    {
      Candidate *c = (Candidate *) i->data;

      if (c->id == candidate_id)
        return c;
    }

  return NULL;
}


static Stream *
_stream_lookup (Agent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = (Stream *) i->data;

      if (s->id == stream_id)
        return s;
    }

  return NULL;
}


/**
 * ice_agent_recv (agent, candidate)
 *
 * Tell the agent to try receiving a packet on @candidate's socket. This is
 * useful for integrating the agent into a select()-loop. This function will
 * block if the socket is blocking.
 */
void
ice_agent_recv (
  Agent *agent,
  guint candidate_id)
{
  Candidate *candidate;
  guint len;
  gchar buf[1024];
  struct sockaddr_in from;

  /* XXX: this is a probably a good place to start optimizing, as it gets
   * called once for each packet recieved
   */

  candidate = _local_candidate_lookup (agent, candidate_id);

  if (candidate == NULL)
    return;

  len = udp_socket_recv (&(candidate->sock), &from,
      sizeof (buf) / sizeof (gchar), buf);
  g_assert (len > 0);

  /* XXX: verify sender; maybe:
   * 
   * if (candidate->other != NULL)
   *   {
   *     if (from != candidate->other.addr)
   *       // ignore packet from unexpected sender
   *       return;
   *   }
   * else
   *   {
   *     // go through remote candidates, looking for one matching packet from
   *     // address; if found, assign it to candidate->other and call handler,
   *     // otherwise ignore it
   *   }
   *
   * Perhaps remote socket affinity is superfluous and all we need is the
   * second part.
   * Perhaps we should also check whether this candidate is supposed to be
   * active.
   */

 /* The top two bits of an RTP message are the version number; the current
  * version number is 2. The top two bits of a STUN message are always 0.
  */

  if ((buf[0] & 0xc0) == 0x80)
    {
      /* looks like RTP */
      Stream *stream;

      stream = _stream_lookup (agent, candidate->stream_id);

      if (stream == NULL)
        /* odd: a candidate that doesn't belong to a stream */
        return;

      /* XXX: should a NULL data handler be permitted? */
      g_assert (stream->handle_recv != NULL);
      stream->handle_recv (agent, candidate->stream_id,
          candidate->component_id, len, buf);
    }
  else if ((buf[0] & 0xc0) == 0)
    {
      StunMessage *msg;

      msg = stun_message_unpack (len, buf);

      if (msg == NULL)
        return;

      if (msg->type == STUN_MESSAGE_BINDING_REQUEST)
        {
          StunMessage *response;
          guint len;
          gchar *packed;

          response = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE);
          memcpy (response->transaction_id, msg->transaction_id, 16);
          response->attributes = g_malloc0 (2 * sizeof (StunAttribute));
          response->attributes[0] = stun_attribute_mapped_address_new (
              ntohl (from.sin_addr.s_addr), ntohs (from.sin_port));
          len = stun_message_pack (response, &packed);
          udp_socket_send (&(candidate->sock), &from, len, packed);

          g_free (packed);
          stun_message_free (response);
        }

      stun_message_free (msg);
    }
}


/*
void
ice_agent_set_stun_server (Address *addr, guint16 port)
{
}
*/

const GSList *
ice_agent_get_local_candidates (
  Agent *agent)
{
  return agent->local_candidates;
}

void
ice_agent_free (Agent *agent)
{
  GSList *i;

  for (i = agent->local_addresses; i; i = i->next)
    {
      Address *a = (Address *) i->data;

      address_free (a);
    }

  g_slist_free (agent->local_addresses);
  agent->local_addresses = NULL;

  for (i = agent->local_candidates; i; i = i->next)
    {
      Candidate *c = (Candidate *) i->data;

      candidate_free (c);
    }

  g_slist_free (agent->local_candidates);
  agent->local_candidates = NULL;

  for (i = agent->remote_candidates; i; i = i->next)
    {
      Candidate *c = (Candidate *) i->data;

      candidate_free (c);
    }

  g_slist_free (agent->remote_candidates);
  agent->remote_candidates = NULL;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = (Stream *) i->data;

      stream_free (s);
    }

  g_slist_free (agent->streams);
  agent->streams = NULL;

  g_slice_free (Agent, agent);
}

