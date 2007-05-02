/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Dafydd Harries, Collabora Ltd.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#include <string.h>
#include <errno.h>

#include <sys/select.h>
#include <sys/socket.h>
#ifndef _BSD_SOURCE
#error "timercmp() macros needed"
#endif
#include <sys/time.h> /* timercmp() macro, BSD */
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include "stun/bind.h"

#include "stun.h"
#include "udp.h"
#include "component.h"
#include "agent.h"
#include "agent-signals-marshal.h"

typedef enum
{
  NICE_CHECK_WAITING = 1,
  NICE_CHECK_IN_PROGRESS,
  NICE_CHECK_SUCCEEDED,
  NICE_CHECK_FAILED,
  NICE_CHECK_FROZEN
} NiceCheckState;

typedef struct _CandidateDiscoveryUDP CandidateDiscoveryUDP;

struct _CandidateDiscoveryUDP
{
  NiceAgent *agent;         /* back pointer to owner */
  NiceCandidateType type;   /* candidate type STUN or TURN */
  int socket;               /* existing socket to use */
  gchar *server_addr;       /* STUN/TURN server address */ 
  NiceAddress *interface;   /* Address of local interface */
  stun_bind_t *ctx;
  GTimeVal next_tick;       /* next tick timestamp */
  gboolean pending;         /* is discovery in progress? */
  gboolean done;            /* is discovery complete? */
  guint stream_id;
  guint component_id;
}; 

typedef struct _CandidatePair CandidatePair;

struct _CandidatePair
{
  NiceAgent *agent;         /* back pointer to owner */
  guint stream_id;
  guint component_id;
  NiceCandidate *local;
  NiceCandidate *remote;
  gchar *foundation;
  NiceCheckState state;
};

#include "stream.h"

typedef enum
{
  CHECK_LIST_STATE_RUNNING,
  CHECK_LIST_STATE_COMPLETED,
} CheckListState;


#define NICE_AGENT_TIMER_TA_DEFAULT 20;     /* timer Ta, msecs */
#define NICE_AGENT_TIMER_TR_DEFAULT 15000;  /* timer Tr, msecs */

G_DEFINE_TYPE (NiceAgent, nice_agent, G_TYPE_OBJECT);


enum
{
  PROP_SOCKET_FACTORY = 1,
  PROP_STUN_SERVER, 
  PROP_STUN_SERVER_PORT,
  PROP_TURN_SERVER, 
  PROP_TURN_SERVER_PORT
};


enum
{
  SIGNAL_COMPONENT_STATE_CHANGED,
  SIGNAL_CANDIDATE_GATHERING_DONE,
  N_SIGNALS,
};


static guint signals[N_SIGNALS];


static Stream *
find_stream (NiceAgent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = i->data;

      if (s->id == stream_id)
        return s;
    }

  return NULL;
}


static gboolean
find_component (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  Stream **stream,
  Component **component)
{
  Stream *s;

  if (component_id != 1)
    return FALSE;

  s = find_stream (agent, stream_id);

  if (s == NULL)
    return FALSE;

  if (stream)
    *stream = s;

  if (component)
    *component = s->component;

  return TRUE;
}


static void
nice_agent_dispose (GObject *object);

static void
nice_agent_get_property (
  GObject *object,
  guint property_id,
  GValue *value,
  GParamSpec *pspec);

static void
nice_agent_set_property (
  GObject *object,
  guint property_id,
  const GValue *value,
  GParamSpec *pspec);


static void
nice_agent_class_init (NiceAgentClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = nice_agent_get_property;
  gobject_class->set_property = nice_agent_set_property;
  gobject_class->dispose = nice_agent_dispose;

  /* install properties */

  g_object_class_install_property (gobject_class, PROP_SOCKET_FACTORY,
      g_param_spec_pointer (
         "socket-factory",
         "UDP socket factory",
         "The socket factory used to create new UDP sockets",
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER,
      g_param_spec_string (
        "stun-server",
        "STUN server",
        "The STUN server used to obtain server-reflexive candidates",
        NULL,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER_PORT,
      g_param_spec_uint (
        "stun-server-port",
        "STUN server port",
        "The STUN server used to obtain server-reflexive candidates",
        1, 65536, 
	3478, /* default port */
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER,
      g_param_spec_string (
        "turn-server",
        "TURN server",
        "The TURN server used to obtain relay candidates",
        NULL,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER_PORT,
      g_param_spec_uint (
        "turn-server-port",
        "TURN server port",
        "The STUN server used to obtain relay candidates",
        1, 65536, 
	3478, /* no default port for TURN, use the STUN default*/
        G_PARAM_READWRITE));

  /* install signals */

  signals[SIGNAL_COMPONENT_STATE_CHANGED] =
      g_signal_new (
          "component-state-changed",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT_UINT,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT,
          G_TYPE_INVALID);

  signals[SIGNAL_CANDIDATE_GATHERING_DONE] =
      g_signal_new (
          "candidate-gathering-done",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__VOID,
          G_TYPE_NONE,
          0,
          G_TYPE_INVALID);
}


static void
nice_agent_init (NiceAgent *agent)
{
  agent->next_candidate_id = 1;
  agent->next_stream_id = 1;

  agent->discovery_unsched_items = 0;

  /* XXX: make configurable */
  agent->full_mode = TRUE;
  agent->discovery_list = NULL;

  agent->rng = nice_rng_new ();
}


/**
 * nice_agent_new:
 * @factory: a NiceUDPSocketFactory used for allocating sockets
 *
 * Create a new NiceAgent.
 *
 * Returns: the new agent
 **/
NiceAgent *
nice_agent_new (NiceUDPSocketFactory *factory)
{
  return g_object_new (NICE_TYPE_AGENT,
      "socket-factory", factory,
      NULL);
}


static void
nice_agent_get_property (
  GObject *object,
  guint property_id,
  GValue *value,
  GParamSpec *pspec)
{
  NiceAgent *agent = NICE_AGENT (object);

  switch (property_id)
    {
    case PROP_SOCKET_FACTORY:
      g_value_set_pointer (value, agent->socket_factory);
      break;

    case PROP_STUN_SERVER:
      g_value_set_string (value, agent->stun_server_ip);

    case PROP_STUN_SERVER_PORT:
      g_value_set_uint (value, agent->stun_server_port);

    case PROP_TURN_SERVER:
      g_value_set_string (value, agent->turn_server_ip);

    case PROP_TURN_SERVER_PORT:
      g_value_set_uint (value, agent->turn_server_port);

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}


static void
nice_agent_set_property (
  GObject *object,
  guint property_id,
  const GValue *value,
  GParamSpec *pspec)
{
  NiceAgent *agent = NICE_AGENT (object);

  switch (property_id)
    {
    case PROP_SOCKET_FACTORY:
      agent->socket_factory = g_value_get_pointer (value);
      break;

    case PROP_STUN_SERVER:
      agent->stun_server_ip = g_value_dup_string (value);
      break;

    case PROP_STUN_SERVER_PORT:
      agent->stun_server_port = g_value_get_uint (value);
      break;

    case PROP_TURN_SERVER:
      agent->turn_server_ip = g_value_dup_string (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static int
nice_agent_get_local_host_candidate_sockfd (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address)
{
  Component *component;
  GSList *i;

  if (!find_component (agent, stream_id, component_id, NULL, &component)) {
    return -1;
  }

  for (i = component->local_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    
    /* note nice_address_equal() also compares the ports and
     * we don't want that here */

    if (address->type == NICE_ADDRESS_TYPE_IPV4 &&
	address->addr_ipv4 == candidate->base_addr.addr_ipv4)
      return candidate->sock.fileno;
  }

  return -1;
}
					    
static void
nice_agent_add_local_host_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address)
{
  NiceCandidate *candidate;
  Component *component;

  if (!find_component (agent, stream_id, component_id, NULL, &component))
    return;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  candidate->id = agent->next_candidate_id++;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = *address;
  component->local_candidates = g_slist_append (component->local_candidates,
      candidate);
  candidate->priority = 
    0x1000000 * 126 + 0x100 * 0 + 256 - component_id; /* sect:4.1.2.1(-14) */

  /* generate username/password */
  nice_rng_generate_bytes_print (agent->rng, 8, candidate->username);
  nice_rng_generate_bytes_print (agent->rng, 8, candidate->password);

  /* allocate socket */
  /* XXX: handle error */
  if (!nice_udp_socket_factory_make (agent->socket_factory,
        &(candidate->sock), address))
    g_assert_not_reached ();

  candidate->addr = candidate->sock.addr;
  candidate->base_addr = candidate->sock.addr;
}

/* compiles but is not called yet */
static void
nice_agent_generate_username_and_password(NiceCandidate *candidate)
{
  NiceRNG *rng;
  /* generate username/password */
  rng = nice_rng_new ();
  nice_rng_generate_bytes_print (rng, 8, candidate->username);
  nice_rng_generate_bytes_print (rng, 8, candidate->password);
  nice_rng_free (rng);
}

static void
nice_agent_add_server_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address)
{
  NiceCandidate *candidate;
  Component *component;

  if (!find_component (agent, stream_id, component_id, NULL, &component))
    return;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
  candidate->id = agent->next_candidate_id++;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = *address;
  component->local_candidates = g_slist_append (component->local_candidates,
      candidate);
  candidate->priority = 
    0x1000000 * 125 + 0x100 * 0 + 256 - component_id; /* sect:4.1.2.1(-14) */

  /* generate username/password */
  nice_agent_generate_username_and_password (candidate);

  /* XXX: how to link to the socket of a local candidate? */
#if 0
  candidate->base_addr = candidate->sock.addr;
#endif
}

static void nice_agent_free_discovery_candidate_udp (gpointer data, gpointer user_data)
{
  CandidateDiscoveryUDP *cand_udp = data;
  g_free (cand_udp->server_addr);
  g_slice_free (CandidateDiscoveryUDP, cand_udp);
}

static void priv_signal_component_state_gathering (NiceAgent *agent, guint stream_id, guint component_id)
{
  Component *component;

  if (!find_component (agent, stream_id, component_id, NULL, &component))
    return;

  if (component->state != NICE_COMPONENT_STATE_GATHERING) {
    component->state = NICE_COMPONENT_STATE_GATHERING;

    g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
		   stream_id, component_id, component->state);
  }
}

#if 0
static void priv_signal_component_state_connecting (NiceAgent *agent, guint stream_id, guint component_id)
{
  Component *component;

  if (!find_component (agent, stream_id, component_id, NULL, &component))
    return;

  if (component->state != NICE_COMPONENT_STATE_CONNECTING) {
    component->state = NICE_COMPONENT_STATE_CONNECTING;

    g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
		   stream_id, component_id, component->state);
  }
}
#endif

/** 
 * Timer callback that handles scheduling new candidate discovery
 * processes (paced by the Ta timer), and handles running of the 
 * existing discovery processes.
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean nice_agent_discovery_tick (gpointer pointer)
{
  CandidateDiscoveryUDP *cand_udp;
  NiceAgent *agent = pointer;
  GSList *i;
  int not_done = 0;

  g_debug ("check tick with list %p (1)", agent->discovery_list);

  for (i = agent->discovery_list; i ; i = i->next) {
    cand_udp = i->data;

    if (cand_udp->pending != TRUE) {
      cand_udp->pending = TRUE;

      if (agent->discovery_unsched_items)
	--agent->discovery_unsched_items;
      
      g_debug ("scheduling cand type %u addr %s and socket %d.\n", cand_udp->type, cand_udp->server_addr, cand_udp->socket);
      
      if (cand_udp->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
	
	struct sockaddr_in stun_server;
	memset (&stun_server, 0, sizeof(stun_server));
	
	/* XXX: using hardcoded server address for now */
	stun_server.sin_addr.s_addr = inet_addr("127.0.0.1");
	stun_server.sin_port = htons(3478);
	int res;

	res = stun_bind_start (&cand_udp->ctx, cand_udp->socket, 
			 (struct sockaddr*)&stun_server, sizeof(stun_server));
	
	if (res == 0) {
	  /* case: success, start waiting for the result */
	  g_get_current_time (&cand_udp->next_tick);

	  priv_signal_component_state_gathering (agent, 
						 cand_udp->stream_id,
						 cand_udp->component_id);

	}
	else {
	  /* case: error in starting discovery, start the next discovery */
	  cand_udp->done = TRUE;
	  continue; 
	}
      }
      else 
	/* allocate relayed candidates */
	g_assert_not_reached ();
      
      ++not_done;
    }
    
    if (cand_udp->done != TRUE) {
      struct sockaddr_in mapped_addr;
      socklen_t socklen = sizeof(mapped_addr);
      GTimeVal now;

      g_get_current_time (&now);

      /* note: macro from sys/time.h but compatible with GTimeVal */
      if (timercmp(&cand_udp->next_tick, &now, <)) {
	int res = stun_bind_resume (cand_udp->ctx, (struct sockaddr*)&mapped_addr, &socklen);
	
	if (res == 0) {
	  /* case: discovery process succesfully completed */
	  NiceAddress *niceaddr;
	  
	  niceaddr = nice_address_new();
	  
	  niceaddr->type = NICE_ADDRESS_TYPE_IPV4;
	  niceaddr->addr_ipv4 = ntohl(mapped_addr.sin_addr.s_addr);
	  niceaddr->port = ntohs(mapped_addr.sin_port);
	  
	  {
	    gchar ip[NICE_ADDRESS_STRING_LEN];
	    
	    nice_address_to_string (niceaddr, ip);
	    g_debug("%s: our public contact address is %s\n", 
		    __func__, ip);
	  }
	  
	  /* XXX: add
	   * g_signal_emit (agent, signals[SIGNAL_NEW_CANDIDATE], 0); */

	  nice_agent_add_server_reflexive_candidate (
						     cand_udp->agent,
						     cand_udp->stream_id,
						     cand_udp->component_id,
						     niceaddr);
	  nice_address_free (niceaddr);
	  cand_udp->done = TRUE;
	}
	else if (res == EAGAIN) {
	  /* case: not ready complete, so schedule next timeout */
	  unsigned int timeout = stun_bind_timeout (cand_udp->ctx);
	  
	  g_get_current_time (&cand_udp->next_tick);
	  g_time_val_add (&cand_udp->next_tick, timeout * 10);
	  
	  /* note: macro from sys/time.h but compatible with GTimeVal */
	  if (timercmp(&cand_udp->next_tick, &agent->next_check_tv, <)) {
	    agent->next_check_tv = cand_udp->next_tick;
	  }
	  
	  ++not_done;
	}
	else {
	  /* case: error, abort processing */
	  cand_udp->done = TRUE;
	}
      }
    }
  }

  if (not_done == 0) {
    g_debug ("Candidate gathering FINISHED, stopping Ta timer.");

    g_slist_foreach (agent->discovery_list, nice_agent_free_discovery_candidate_udp, NULL);
    g_slist_free (agent->discovery_list),
      agent->discovery_list = NULL;

    g_signal_emit (agent, signals[SIGNAL_CANDIDATE_GATHERING_DONE], 0);

    /* note: no pending timers, return FALSE to stop timer */
    return FALSE;
  }

  return TRUE;
}

static void nice_agent_schedule_discovery (NiceAgent *agent)
{
  if (agent->discovery_list) {
    GTimeVal now;

    /* XXX: make timeout Ta configurable */
    guint next = NICE_AGENT_TIMER_TA_DEFAULT; 

    if (agent->discovery_unsched_items == 0)
      next = (guint)-1;

    /* XXX: send a component state-change, but, but, how do we
     * actually do this? back to the drawing board... */
    /* 
     *    Component *component;
     * if (!find_component (agent, stream_id, component_id, &stream, &component))
     *  return 0;
     *
     * component->state = NICE_COMPONENT_STATE_GATHERING;
     *
     * g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
     * cand_stream->id, component->id, component->state);
     */

    nice_agent_discovery_tick (agent);

    g_get_current_time (&now);
	
    guint msecs = (agent->next_check_tv.tv_sec - now.tv_sec) * 1000;
    msecs += (agent->next_check_tv.tv_usec - now.tv_usec) / 1000;

    if (msecs < next)
      next = msecs;

    g_debug ("Scheduling a timeout of %u msec.", next);

    g_timeout_add (next, nice_agent_discovery_tick, agent);
  }
}

/**
 * nice_agent_add_stream:
 *  @agent: a NiceAgent
 *  @handle_recv: a function called when the stream recieves data
 *  @handle_recv_data: data passed as last parameter to @handle_recv
 *
 * Add a data stream to @agent.
 *
 * Returns: the ID of the new stream
 **/
guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components)
{
  Stream *stream;
  GSList *i;

  g_assert (n_components == 1);

  if (!agent->streams) {
    /* note: this contains a Y2038 issue */
    agent->next_check_tv.tv_sec = 
      agent->next_check_tv.tv_usec = (long)-1;
  }

  stream = stream_new ();
  stream->id = agent->next_stream_id++;
  agent->streams = g_slist_append (agent->streams, stream);

  /* generate a local host candidate for each local address */

  if (agent->full_mode) {
    g_debug ("In FULL mode, starting candidate gathering.\n");
  }

  for (i = agent->local_addresses; i; i = i->next)
    {
      NiceAddress *addr = i->data;
      CandidateDiscoveryUDP *cand_udp;
      int sockfd;

      nice_agent_add_local_host_candidate (agent, stream->id,
          stream->component->id, addr);

      if (agent->full_mode) {
	sockfd = nice_agent_get_local_host_candidate_sockfd (agent, stream->id, stream->component->id, addr);

	/* XXX: need to check for redundant candidates? -> not yet,
	 *  this is done later on */
	
	cand_udp = g_slice_new0 (CandidateDiscoveryUDP);
	cand_udp->type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
	cand_udp->socket = sockfd;
	cand_udp->server_addr = g_strdup ("127.0.0.1" /*"stunserver.org"*/);
	cand_udp->interface = addr;
	cand_udp->stream_id = stream->id;
	cand_udp->component_id = stream->component->id;
	cand_udp->agent = agent;
	g_debug ("Adding srv-rflx candidate %p\n", cand_udp);
	agent->discovery_list = g_slist_append (agent->discovery_list, cand_udp);
	++agent->discovery_unsched_items;
      }

      /* XXX-later: send STUN requests to obtain server-reflexive candidates */
    }

  if (agent->discovery_list)
    nice_agent_schedule_discovery (agent);

  return stream->id;
}

/**
 * nice_agent_remove_stream:
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream to remove
 **/
void
nice_agent_remove_stream (
  NiceAgent *agent,
  guint stream_id)
{
  /* note that streams/candidates can be in use by other threads */

  Stream *stream;

  stream = find_stream (agent, stream_id);

  if (!stream)
    return;

  /* remove stream */

  stream_free (stream);
  agent->streams = g_slist_remove (agent->streams, stream);
}


/**
 * nice_agent_add_local_address:
 *  @agent: A NiceAgent
 *  @addr: the address of a local IP interface
 *
 * Inform the agent of the presence of an address that a local network
 * interface is bound to.
 **/
void
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr)
{
  NiceAddress *dup;

  dup = nice_address_dup (addr);
  dup->port = 0;
  agent->local_addresses = g_slist_append (agent->local_addresses, dup);

  /* XXX: Should we generate local candidates for existing streams at this
   * point, or require that local addresses are set before media streams are
   * added?
   */
}

static gboolean nice_agent_conn_check_tick (gpointer pointer)
{
  /* XXX: placeholder, implementation not done */

  g_debug ("%s: stopping timer", G_STRFUNC);
  return FALSE;
}

/**
 * Schedules the next timer tick for connectivity checks.
 */
static void priv_schedule_conn_checks (NiceAgent *agent)
{
  /* XXX: placeholder, implementation not done */

  g_timeout_add (1, nice_agent_conn_check_tick, agent);
}

/**
 * Forms new candidate pairs by matching the new remote candidate
 * 'remote_cand' with all existing local candidates of 'component'.
 * Implements the logic described in sect 5.7.1 of ICE -15 spec.
 */
static void priv_add_conn_checks (NiceAgent *agent, Component *component, NiceCandidate *remote_cand)
{
  GSList *i;

  for (i = component->local_candidates; i ; i = i->next) {
    /* XXX: steps:
     * - form a new candidate pair item (CandidatePair)
     * - add it, filtered/pruned, to the check list
     * - schedule the next timeout (priv_schedule_conn_checks())
     */

    /* XXX: to keep the compiler happy until implementation is done */
    NiceCandidate *cand = i->data;
    cand = NULL;
  }

  priv_schedule_conn_checks (agent);
}

static void priv_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  const NiceAddress *addr,
  const NiceAddress *related_addr,
  NiceCandidateTransport transport,
  guint32 priority,
  const gchar *username,
  const gchar *password,
  const gchar *foundation)
{
  Component *component;
  NiceCandidate *candidate;

  if (!find_component (agent, stream_id, component_id, NULL, &component))
    return;

  candidate = nice_candidate_new (type);

  candidate->stream_id = stream_id;
  candidate->component_id = component_id;

  /* note: always zero, foundation used to identify remote cands */
  candidate->id = 0; 

  candidate->type = type;
  if (addr)
    candidate->addr = *addr;
  if (related_addr)
    candidate->base_addr = *related_addr;

  candidate->transport = transport;

  /* XXX: ugh, ugh, fixed size fields */
  if (username)
    strncpy (candidate->username, username, sizeof (candidate->username));
  if (password)
    strncpy (candidate->password, password, sizeof (candidate->password));
  if (foundation)
    candidate->foundation = g_strdup (foundation);

  component->remote_candidates = g_slist_append (component->remote_candidates,
      candidate);

  priv_add_conn_checks (agent, component, candidate);

}

/**
 * nice_agent_add_remote_candidate
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream the candidate is for
 *  @component_id: the ID of the component the candidate is for
 *  @type: the type of the new candidate
 *  @addr: the new candidate's IP address
 *  @port: the new candidate's port
 *  @username: the new candidate's username
 *  @password: the new candidate's password
 *
 * Add a candidate our peer has informed us about to the agent's list.
 **/
void
nice_agent_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  NiceAddress *addr,
  const gchar *username,
  const gchar *password)
{
  priv_add_remote_candidate (agent,
			     stream_id,
			     component_id,
			     type,
			     addr,
			     NULL,
			     NICE_CANDIDATE_TRANSPORT_UDP,
			     0,
			     username,
			     password,
			     NULL);

  /* later: for each component, generate a new check with the new
     candidate */
}

/**
 * nice_agent_set_remote_candidates
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream the candidate is for
 *  @component_id: the ID of the component the candidate is for
 *  @candidates: a list of NiceCandidateDesc items describing the candidates
 *
 * Sets the remote candidates for a component of a stream. Replaces
 * any existing remote candidates.
 **/
void
nice_agent_set_remote_candidates (NiceAgent *agent, guint stream_id, guint component_id, GSList *candidates)
{
 GSList *i; 

 /* XXX: clean up existing remote candidates, and abort any 
  *      connectivity checks using these candidates */

 for (i = candidates; i; i = i->next) {
   NiceCandidateDesc *d = (NiceCandidateDesc*) i->data;
   priv_add_remote_candidate (agent,
			      stream_id,
			      component_id,
			      d->type,
			      d->addr,
			      d->related_addr,
			      d->transport,
			      d->priority,
			      NULL,
			      NULL,
			      d->foundation);
 }
}

#if 0
static NiceCandidate *
_local_candidate_lookup (NiceAgent *agent, guint candidate_id)
{
  GSList *i;

  for (i = agent->local_candidates; i; i = i->next)
    {
      NiceCandidate *c = i->data;

      if (c->id == candidate_id)
        return c;
    }

  return NULL;
}
#endif


static NiceCandidate *
find_candidate_by_fd (Component *component, guint fd)
{
  GSList *i;

  for (i = component->local_candidates; i; i = i->next)
    {
      NiceCandidate *c = i->data;

      if (c->sock.fileno == fd)
        return c;
    }

  return NULL;
}


static void
_handle_stun_binding_request (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceCandidate *local,
  NiceAddress from,
  StunMessage *msg)
{
  GSList *i;
  StunAttribute *attr;
  gchar *username = NULL;
  NiceCandidate *remote = NULL;

  /* msg should have either:
   *
   *   Jingle P2P:
   *     username = local candidate username + remote candidate username
   *   ICE:
   *     username = local candidate username + ":" + remote candidate username
   *     password = local candidate pwd
   *     priority = priority to use if a new candidate is generated
   *
   * Note that:
   *
   *  - "local"/"remote" are from the perspective of the receiving side
   *  - the remote candidate username is not necessarily unique; Jingle seems
   *    to always generate a unique username/password for each candidate, but
   *    ICE makes no guarantees
   *
   * There are three cases we need to deal with:
   *
   *  - valid username with a known address
   *    --> send response
   *  - valid username with an unknown address
   *    --> send response
   *    --> later: create new remote candidate
   *  - invalid username
   *    --> send error
   */

  /* XXX-KV: update to use Remi's implementation */

  attr = stun_message_find_attribute (msg, STUN_ATTRIBUTE_USERNAME);

  if (attr == NULL)
    /* no username attribute found */
    goto ERROR;

  username = attr->username;

  /* validate username */
  /* XXX: Should first try and find a remote candidate with a matching
   * transport address, and fall back to matching on username only after that.
   * That way, we know to always generate a new remote candidate if the
   * transport address didn't match.
   */

  for (i = component->remote_candidates; i; i = i->next)
    {
      guint len;

      remote = i->data;

#if 0
      g_debug ("uname check: %s :: %s -- %s", username, local->username,
          remote->username);
#endif

      if (!g_str_has_prefix (username, local->username))
        continue;

      len = strlen (local->username);

      if (0 != strcmp (username + len, remote->username))
        continue;

#if 0
      /* usernames match; check address */

      if (rtmp->addr.addr_ipv4 == ntohl (from.sin_addr.s_addr) &&
          rtmp->port == ntohs (from.sin_port))
        {
          /* this is a candidate we know about, just send a reply */
          /* is candidate pair active now? */
          remote = rtmp;
        }
#endif

      /* send response */
      goto RESPOND;
    }

  /* username is not valid */
  goto ERROR;

RESPOND:

#ifdef DEBUG
    {
      gchar ip[NICE_ADDRESS_STRING_LEN];

      nice_address_to_string (&remote->addr, ip);
      g_debug ("s%d:%d: got valid connectivity check for candidate %d (%s:%d)",
          stream->id, component->id, remote->id, ip, remote->addr.port);
    }
#endif

  /* update candidate/peer affinity */
  /* Note that @from might be different to @remote->addr; for ICE, this
   * (always?) creates a new peer-reflexive remote candidate (§7.2).
   */
  /* XXX: test case where @from != @remote->addr. */

  component->active_candidate = local;
  component->peer_addr = from;

  /* send STUN response */

    {
      StunMessage *response;
      guint len;
      gchar *packed;

      /* XXX-KV: update to use Remi's implementation */

      response = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE,
          msg->transaction_id, 2);
      response->attributes[0] = stun_attribute_mapped_address_new (
          from.addr_ipv4, from.port);
      response->attributes[1] = stun_attribute_username_new (username);
      len = stun_message_pack (response, &packed);
      nice_udp_socket_send (&local->sock, &from, len, packed);

      g_free (packed);
      stun_message_free (response);
    }

  /* send reciprocal ("triggered") connectivity check */
  /* XXX: possibly we shouldn't do this if we're being an ICE Lite agent */

    {
      StunMessage *extra;
      gchar *username;
      guint len;
      gchar *packed;

      /* XXX-KV: update to use Remi's implementation */

      extra = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          NULL, 1);

      username = g_strconcat (remote->username, local->username, NULL);
      extra->attributes[0] = stun_attribute_username_new (username);
      g_free (username);

      nice_rng_generate_bytes (agent->rng, 16, extra->transaction_id);

      len = stun_message_pack (extra, &packed);
      nice_udp_socket_send (&local->sock, &from, len, packed);
      g_free (packed);

      stun_message_free (extra);
    }

  /* emit component-state-changed(connected) */
  /* XXX: probably better do this when we get the binding response */

    {
      if (component->state != NICE_COMPONENT_STATE_CONNECTED)
        {
          component->state = NICE_COMPONENT_STATE_CONNECTED;
          g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
              stream->id, component->id, component->state);
        }
    }

  return;

ERROR:

#ifdef DEBUG
    {
      gchar ip[NICE_ADDRESS_STRING_LEN];

      nice_address_to_string (&remote->addr, ip);
      g_debug (
          "s%d:%d: got invalid connectivity check for candidate %d (%s:%d)",
          stream->id, component->id, remote->id, ip, remote->addr.port);
    }
#endif

  /* XXX: add ERROR-CODE parameter */

    {
      StunMessage *response;
      guint len;
      gchar *packed;

      /* XXX-KV: update to use Remi's implementation */

      response = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          msg->transaction_id, 0);
      len = stun_message_pack (response, &packed);
      nice_udp_socket_send (&local->sock, &from, len, packed);

      g_free (packed);
      stun_message_free (response);
    }

  /* XXX: we could be clever and keep around STUN packets that we couldn't
   * validate, then re-examine them when we get new remote candidates -- would
   * this fix some timing problems (i.e. TCP being slower than UDP)
   */
  /* XXX: if the peer is the controlling agent, it may include a USE-CANDIDATE
   * attribute in the binding request
   */
}


static void
_handle_stun (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceCandidate *local,
  NiceAddress from,
  StunMessage *msg)
{
  switch (msg->type)
    {
    case STUN_MESSAGE_BINDING_REQUEST:
      _handle_stun_binding_request (agent, stream, component, local, from,
          msg);
      break;
    case STUN_MESSAGE_BINDING_RESPONSE:
      /* XXX: check it matches a request we sent */
      break;
    default:
      /* a message type we don't know how to handle */
      /* XXX: send error response */
      break;
    }
}


static guint
_nice_agent_recv (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceCandidate *candidate,
  guint buf_len,
  gchar *buf)
{
  NiceAddress from;
  guint len;

  len = nice_udp_socket_recv (&(candidate->sock), &from,
      buf_len, buf);

  if (len == 0)
    return 0;

  if (len > buf_len)
    {
      /* buffer is not big enough to accept this packet */
      /* XXX: test this case */
      return 0;
    }

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
      return len;
    }
  else if ((buf[0] & 0xc0) == 0)
    {
      /* looks like a STUN message (connectivity check) */
      /* connectivity checks are described in ICE-13 §7. */
      StunMessage *msg;

      /* XXX-KV: update to use Remi's implementation */

      msg = stun_message_unpack (len, buf);

      if (msg != NULL)
        {
          _handle_stun (agent, stream, component, candidate, from, msg);
          stun_message_free (msg);
        }
    }

  /* anything else is ignored */
  return 0;
}


/**
 * nice_agent_recv:
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream to recieve data from
 *  @component_id: the ID of the component to receive data from
 *  @buf_len: the size of @buf
 *  @buf: the buffer to read data into
 *
 * Recieve data on a particular component.
 *
 * Returns: the amount of data read into @buf
 **/
guint
nice_agent_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint buf_len,
  gchar *buf)
{
  guint len = 0;
  fd_set fds;
  guint max_fd = 0;
  gint num_readable;
  GSList *i;
  Stream *stream;
  Component *component;

  if (!find_component (agent, stream_id, component_id, &stream, &component))
    return 0;

  FD_ZERO (&fds);

  for (i = component->local_candidates; i; i = i->next)
    {
      NiceCandidate *candidate = i->data;

      FD_SET (candidate->sock.fileno, &fds);
      max_fd = MAX (candidate->sock.fileno, max_fd);
    }

  /* Loop on candidate sockets until we find one that has non-STUN data
   * waiting on it.
   */

  for (;;)
    {
      num_readable = select (max_fd + 1, &fds, NULL, NULL, NULL);
      g_assert (num_readable >= 0);

      if (num_readable > 0)
        {
          guint j;

          for (j = 0; j <= max_fd; j++)
            if (FD_ISSET (j, &fds))
              {
                NiceCandidate *candidate;

                candidate = find_candidate_by_fd (component, j);
                g_assert (candidate);
                len = _nice_agent_recv (agent, stream, component, candidate,
                    buf_len, buf);

                if (len > 0)
                  return len;
              }
        }
    }

  g_assert_not_reached ();
}


guint
nice_agent_recv_sock (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint sock,
  guint buf_len,
  gchar *buf)
{
  NiceCandidate *candidate;
  Stream *stream;
  Component *component;

  if (!find_component (agent, stream_id, component_id, &stream, &component))
    return 0;

  candidate = find_candidate_by_fd (component, sock);
  g_assert (candidate);

  return _nice_agent_recv (agent, stream, stream->component,
      candidate, buf_len, buf);
}


/**
 * nice_agent_poll_read:
 *  @agent: A NiceAgent
 *  @other_fds: A GSList of other file descriptors to poll
 *
 * Polls the agent's sockets until at least one of them is readable, and
 * additionally if @other_fds is not NULL, polls those for readability too.
 * @other_fds should contain the file descriptors directly, i.e. using
 * GUINT_TO_POINTER.
 *
 * Returns: A list of file descriptors from @other_fds that are readable
 **/
GSList *
nice_agent_poll_read (
  NiceAgent *agent,
  GSList *other_fds,
  NiceAgentRecvFunc func,
  gpointer data)
{
  fd_set fds;
  guint max_fd = 0;
  gint num_readable;
  GSList *ret = NULL;
  GSList *i;
  guint j;

  FD_ZERO (&fds);

  for (i = agent->streams; i; i = i->next)
    {
      GSList *j;
      Stream *stream = i->data;
      Component *component = stream->component;

      for (j = component->local_candidates; j; j = j->next)
        {
          NiceCandidate *candidate = j->data;

          FD_SET (candidate->sock.fileno, &fds);
          max_fd = MAX (candidate->sock.fileno, max_fd);
        }
    }

  for (i = other_fds; i; i = i->next)
    {
      guint fileno;

      fileno = GPOINTER_TO_UINT (i->data);
      FD_SET (fileno, &fds);
      max_fd = MAX (fileno, max_fd);
    }

  num_readable = select (max_fd + 1, &fds, NULL, NULL, NULL);

  if (num_readable < 1)
    /* none readable, or error */
    return NULL;

  for (j = 0; j <= max_fd; j++)
    if (FD_ISSET (j, &fds))
      {
        if (g_slist_find (other_fds, GUINT_TO_POINTER (j)))
          ret = g_slist_append (ret, GUINT_TO_POINTER (j));
        else
          {
            NiceCandidate *candidate = NULL;
            Stream *stream;
            gchar buf[1024];
            guint len;

            for (i = agent->streams; i; i = i->next)
              {
                Stream *s = i->data;
                Component *c = s->component;

                candidate = find_candidate_by_fd (c, j);

                if (candidate != NULL)
                  break;
              }

            if (candidate == NULL)
              break;

            stream = find_stream (agent, candidate->stream_id);

            if (stream == NULL)
              break;

            len = _nice_agent_recv (agent, stream, stream->component,
                candidate, 1024, buf);

            if (len && func != NULL)
              func (agent, stream->id, candidate->component_id, len, buf,
                  data);
          }
      }

  return ret;
}


void
nice_agent_send (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  const gchar *buf)
{
  Stream *stream;
  Component *component;

  stream = find_stream (agent, stream_id);
  component = stream->component;

  if (component->active_candidate != NULL)
    {
      NiceUDPSocket *sock;
      NiceAddress *addr;

#if 0
      g_debug ("s%d:%d: sending %d bytes to %08x:%d", stream_id, component_id,
          len, component->peer_addr->addr_ipv4, component->peer_addr->port);
#endif

      sock = &component->active_candidate->sock;
      addr = &component->peer_addr;
      nice_udp_socket_send (sock, addr, len, buf);
    }
}


/**
 * nice_agent_get_local_candidates:
 *  @agent: A NiceAgent
 *
 * The caller owns the returned GSList but not the candidates contained within
 * it.
 *
 * Returns: a GSList of local candidates belonging to @agent
 **/
GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id)
{
  Component *component;

  if (!find_component (agent, stream_id, component_id, NULL, &component))
    return NULL;

  return g_slist_copy (component->local_candidates);
}


/**
 * nice_agent_get_remote_candidates:
 *  @agent: A NiceAgent
 *
 * The caller owns the returned GSList but not the candidates contained within
 * it.
 *
 * Returns: a GSList of remote candidates belonging to @agent
 **/
GSList *
nice_agent_get_remote_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id)
{
  Component *component;

  if (!find_component (agent, stream_id, component_id, NULL, &component))
    return NULL;

  /* XXX: should we expose NiceCandidate to the client, or should
   *      we instead return a list of NiceCandidateDesc's? */

  return g_slist_copy (component->remote_candidates);
}


static void
nice_agent_dispose (GObject *object)
{
  GSList *i;
  NiceAgent *agent = NICE_AGENT (object);

  if (agent->discovery_list) {
    g_slist_foreach (agent->discovery_list, nice_agent_free_discovery_candidate_udp, NULL);
    g_slist_free (agent->discovery_list),
      agent->discovery_list = NULL;
  }

  for (i = agent->local_addresses; i; i = i->next)
    {
      NiceAddress *a = i->data;

      nice_address_free (a);
    }

  g_slist_free (agent->local_addresses);
  agent->local_addresses = NULL;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = i->data;

      stream_free (s);
    }

  g_slist_free (agent->streams);
  agent->streams = NULL;

  g_free (agent->stun_server_ip);
  agent->stun_server_ip = NULL;

  nice_rng_free (agent->rng);
  agent->rng = NULL;

  if (G_OBJECT_CLASS (nice_agent_parent_class)->dispose)
    G_OBJECT_CLASS (nice_agent_parent_class)->dispose (object);
}


typedef struct _IOCtx IOCtx;

struct _IOCtx
{
  NiceAgent *agent;
  Stream *stream;
  Component *component;
  NiceCandidate *candidate;
};


static IOCtx *
io_ctx_new (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceCandidate *candidate)
{
  IOCtx *ctx;

  ctx = g_slice_new0 (IOCtx);
  ctx->agent = agent;
  ctx->stream = stream;
  ctx->component = component;
  ctx->candidate = candidate;
  return ctx;
}


static void
io_ctx_free (IOCtx *ctx)
{
  g_slice_free (IOCtx, ctx);
}


static gboolean
nice_agent_g_source_cb (
  GIOChannel *source,
  G_GNUC_UNUSED
  GIOCondition condition,
  gpointer data)
{
  /* return value is whether to keep the source */

  IOCtx *ctx = data;
  NiceAgent *agent = ctx->agent;
  Stream *stream = ctx->stream;
  Component *component = ctx->component;
  NiceCandidate *candidate = ctx->candidate;
  gchar buf[1024];
  guint len;

  len = _nice_agent_recv (agent, stream, component, candidate, 1024,
      buf);

  if (len > 0)
    agent->read_func (agent, candidate->stream_id, candidate->component_id,
        len, buf, agent->read_func_data);

  return TRUE;
}


gboolean
nice_agent_main_context_attach (
  NiceAgent *agent,
  GMainContext *ctx,
  NiceAgentRecvFunc func,
  gpointer data)
{
  GSList *i;

  if (agent->main_context_set)
    return FALSE;

  /* attach candidates */

  for (i = agent->streams; i; i = i->next)
    {
      GSList *j;
      Stream *stream = i->data;
      Component *component = stream->component;

      for (j = component->local_candidates; j; j = j->next)
        {
          NiceCandidate *candidate = j->data;
          GIOChannel *io;
          GSource *source;
          IOCtx *ctx;

          io = g_io_channel_unix_new (candidate->sock.fileno);
          source = g_io_create_watch (io, G_IO_IN);
          ctx = io_ctx_new (agent, stream, component, candidate);
          g_source_set_callback (source, (GSourceFunc) nice_agent_g_source_cb,
              ctx, (GDestroyNotify) io_ctx_free);
          g_source_attach (source, NULL);
          candidate->source = source;
        }
    }

  agent->main_context = ctx;
  agent->main_context_set = TRUE;
  agent->read_func = func;
  agent->read_func_data = data;
  return TRUE;
}
