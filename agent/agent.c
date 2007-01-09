
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include <agent.h>

/*** address ***/

typedef enum address_type AddressType;

enum address_type
{
  ADDRESS_TYPE_IPV4,
  ADDRESS_TYPE_IPV6,
};


struct _address
{
  enum address_type type;
  union
  {
    guint32 addr_ipv4;
    guchar addr_ipv6[16];
  };
};


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
    return address_new_ipv4 (iaddr.s_addr);
  else
    /* invalid address */
    return NULL;
}


gchar *
address_to_string (Address *addr)
{
  struct in_addr iaddr;

  g_assert (addr->type == ADDRESS_TYPE_IPV4);
  iaddr.s_addr = addr->addr_ipv4;
  return g_strdup (inet_ntoa (iaddr));
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
candidate_new (enum candidate_type type)
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
enum component_type
{
  COMPONENT_TYPE_RTP,
  COMPONENT_TYPE_RTCP,
};


typedef struct _component Component;

struct _component
{
  enum component_type type;
  guint id;
};


static Component *
component_new (enum component_type type)
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
  enum media_type type;
  /* XXX: streams can have multiple components */
  Component *component;
};


Stream *
stream_new (enum media_type type)
{
  Stream *stream;

  stream = g_slice_new0 (Stream);
  stream->type = type;
  stream->component = component_new (COMPONENT_TYPE_RTP);
  return stream;
}


void
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


/* ICE12 §6.7 (p24) */
enum check_state
{
  CHECK_STATE_WAITING,
  CHECK_STATE_IN_PROGRESS,
  CHECK_STATE_SUCCEEDED,
  CHECK_STATE_FAILED,
  CHECK_STATE_FROZEN,
};


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


static Event *
event_new (enum event_type type)
{
  Event *ev;

  ev = g_slice_new0 (Event);
  ev->type = type;
  return ev;
}


static Event *
event_new_request_port (Address *addr, guint candidate_id)
{
  Event *ev;

  ev = event_new (EVENT_REQUEST_PORT);
  ev->request_port.addr = address_dup (addr);
  ev->request_port.candidate_id = candidate_id;
  return ev;
}


static Event *
event_new_local_candidates_ready ()
{
  return event_new (EVENT_LOCAL_CANDIDATES_READY);
}

void
event_free (Event *ev)
{
  switch (ev->type)
    {
      case EVENT_REQUEST_PORT:
        address_free (ev->request_port.addr);
        break;

      case EVENT_LOCAL_CANDIDATES_READY:
        break;

      case EVENT_REQUEST_STUN_QUERY:
        address_free (ev->request_stun_query.from);
        address_free (ev->request_stun_query.to);
        break;

      case EVENT_CANDIDATE_SELECTED:
        break;
    }

  g_slice_free (Event, ev);
}


/*** agent ***/


Agent *
ice_agent_new ()
{
  Agent *agent;

  agent = g_slice_new0 (Agent);
  agent->next_candidate_id = 1;
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


//void
//ice_agent_add_component (enum media_type type)
//{
//  /* generate candidates for component × local interfaces */
//}


static void
ice_agent_add_local_host_candidate (
  Agent *agent,
  Component *component,
  Address *address)
{
  Candidate *candidate;

  candidate = candidate_new (CANDIDATE_TYPE_HOST);
  candidate->id = agent->next_candidate_id++;
  candidate->addr = address_dup (address);
  candidate->base_addr = address_dup (address);
  agent->local_candidates = g_slist_append (agent->local_candidates,
      candidate);

  /* request port for new candidate */
  ice_agent_push_event (agent,
      event_new_request_port (address, candidate->id));
}


/* XXX: check that ID given matches one of the candidates we have? */
void
ice_agent_set_candidate_port (Agent *agent, guint candidate_id, guint port)
{
  GSList *i;
  gboolean local_candidates_ready = TRUE;

  for (i = agent->local_candidates; i; i = i->next)
    {
      Candidate *c = (Candidate *) i->data;

      if (c->id == candidate_id)
        c->port = port;
      else if (c->port == 0)
        local_candidates_ready = FALSE;
    }

  if (local_candidates_ready)
    ice_agent_push_event (agent, event_new_local_candidates_ready ());
}


void
ice_agent_add_stream (Agent *agent, enum media_type type)
{
  Stream *stream;
  GSList *i;

  stream = stream_new (type);
  agent->streams = g_slist_append (agent->streams, stream);

  /* generate a local host candidate for each local address */

  for (i = agent->local_addresses; i; i = i->next)
    {
      Address *addr = (Address *) i->data;

      ice_agent_add_local_host_candidate (agent, stream->component, addr);

      /* XXX: need to check for redundant candidates? */
      /* later: send STUN requests to obtain server-reflexive candidates */
    }
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
ice_agent_add_remote_candidate (Agent *a, Candidate *c)
{
  /* append to agent->remote_candidates */
  /* for each component, generate a new check with the new candidate */
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

  /*
  for (i = agent->remote_candidates; i; i = i->next)
    {
      Candidate *c = (Candidate *) i->data;

      candidate_free (c);
    }

  g_slist_free (agent->remote_candidates);
  agent->remote_candidates = NULL;
  */

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


