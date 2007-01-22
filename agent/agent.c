
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

#include <agent.h>

/*** address ***/


Address *
address_new_ipv4 (guint32 addr_ipv4)
{
  Address *addr;

  addr = g_slice_new0 (Address);
  addr->addr_ipv4 = addr_ipv4;
  return addr;
}


/**
 * address_new_ipv4_from_string ()
 *
 * Returns NULL on error.
 */
Address *
address_new_ipv4_from_string (gchar *str)
{
  struct in_addr iaddr;

  if (inet_aton (str, &iaddr) != 0)
    return address_new_ipv4 (ntohl (iaddr.s_addr));
  else
    /* invalid address */
    return NULL;
}


gchar *
address_to_string (Address *addr)
{
  struct in_addr iaddr;
  gchar ip_str[INET_ADDRSTRLEN];
  const gchar *ret;

  g_assert (addr->type == ADDRESS_TYPE_IPV4);
  iaddr.s_addr = htonl (addr->addr_ipv4);
  ret = inet_ntop (AF_INET, &iaddr, ip_str, INET_ADDRSTRLEN);
  g_assert (ret);
  return g_strdup (ip_str);
}


gboolean
address_equal (Address *a, Address *b)
{
  return memcmp (a, b, sizeof (Address)) == 0;
}


Address *
address_dup (Address *a)
{
  Address *dup = g_slice_new0 (Address);

  *dup = *a;
  return dup;
}


void
address_free (Address *addr)
{
  g_slice_free (Address, addr);
}


/* "private" in the sense of "not routable on the Internet" */
static gboolean
ipv4_address_is_private (guint32 addr)
{
  /* http://tools.ietf.org/html/rfc3330 */
  return (
      /* 10.0.0.0/8 */
      ((addr & 0xff000000) == 0x0a000000) ||
      /* 172.16.0.0/12 */
      ((addr & 0xfff00000) == 0xac100000) ||
      /* 192.168.0.0/16 */
      ((addr & 0xffff0000) == 0xc0a80000) ||
      /* 127.0.0.0/8 */
      ((addr & 0xff000000) == 0x7f000000));
}


gboolean
address_is_private (Address *a)
{
  if (a->type == ADDRESS_TYPE_IPV4)
    return ipv4_address_is_private (a->addr_ipv4);

  g_assert_not_reached ();
}


/*** candidate ***/


/* (ICE12 §5.1) Every candidate is a transport address. It also has a type and
 * a base. Three types are defined and gathered by this specification - host
 * candidates, server reflexive candidates, and relayed candidates. */


Candidate *
candidate_new (CandidateType type)
{
  Candidate *candidate;

  candidate = g_slice_new0 (Candidate);
  candidate->type = type;
  return candidate;
}


void
candidate_free (Candidate *candidate)
{
  address_free (candidate->addr);
  address_free (candidate->base_addr);
  g_slice_free (Candidate, candidate);
}


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
  MediaType type;
  guint id;
  /* XXX: streams can have multiple components */
  Component *component;
  void (*handle_recv) (Agent *agent, guint stream_id, guint len, gchar *buf);
};


static Stream *
stream_new (MediaType type)
{
  Stream *stream;

  stream = g_slice_new0 (Stream);
  stream->type = type;
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


/* ICE12 §5.2 */
guint64
candidate_priority (
    guint type_preference,
    guint local_preference,
    guint component_id)
{
  return (
      0x1000000 * type_preference +
      0x100 * local_preference +
      (256 - component_id));
}


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
  candidate->addr = address_dup (address);
  candidate->base_addr = address_dup (address);
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
  MediaType type,
  void (*handle_recv) (Agent *agent, guint stream_id, guint len, gchar *buf))
{
  Stream *stream;
  GSList *i;

  stream = stream_new (type);
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
  candidate->addr = address_dup (addr);
  candidate->port = port;

  agent->remote_candidates = g_slist_append (agent->remote_candidates,
      candidate);

  /* later: for each component, generate a new check with the new candidate */
}


/*
void
ice_agent_set_stun_server (Address *addr, guint16 port)
{
}


void
ice_agent_handle_packet (
  Agent *agent,
  Address *from,
  guint length,
  gchar *buffer)
{
}
*/


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


/*
void
ice_agent_got_stun_response (
  Agent *agent,
  Address *from,
  guint from_port,
  Address *to,
  guint to_port)
{
}


void
ice_agent_got_stun_request (
  Agent *agent,
  Address *from,
  guint from_port,
  Address *to,
  guint to_port)
{
}
*/


