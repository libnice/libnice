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
 *   Kai Vehmanen, Nokia
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
#include "candidate.h"
#include "component.h"
#include "conncheck.h"
#include "discovery.h"
#include "agent.h"
#include "agent-priv.h"
#include "agent-signals-marshal.h"

#include "stream.h"


G_DEFINE_TYPE (NiceAgent, nice_agent, G_TYPE_OBJECT);

enum
{
  PROP_SOCKET_FACTORY = 1,
  PROP_STUN_SERVER, 
  PROP_STUN_SERVER_PORT,
  PROP_TURN_SERVER, 
  PROP_TURN_SERVER_PORT,
  PROP_CONTROLLING_MODE,
  PROP_FULL_MODE
};


enum
{
  SIGNAL_COMPONENT_STATE_CHANGED,
  SIGNAL_CANDIDATE_GATHERING_DONE,
  SIGNAL_NEW_SELECTED_PAIR,
  SIGNAL_NEW_CANDIDATE,
  SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED,
  N_SIGNALS,
};


static guint signals[N_SIGNALS];

static gboolean priv_attach_new_stream (NiceAgent *agent, Stream *stream);
static void priv_deattach_stream (Stream *stream);

Stream *agent_find_stream (NiceAgent *agent, guint stream_id)
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


gboolean
agent_find_component (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  Stream **stream,
  Component **component)
{
  Stream *s;

  if (component_id != 1)
    return FALSE;

  s = agent_find_stream (agent, stream_id);

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
  
  /* XXX: add properties:
   *  - Ta-timer (construct-property, msec) 
   *  - make the others construct-time only as well...?
   */ 

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
	IPPORT_STUN, /* default port */
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

  g_object_class_install_property (gobject_class, PROP_CONTROLLING_MODE,
      g_param_spec_boolean (
        "controlling-mode",
        "ICE controlling mode",
        "Whether the agent is in controlling mode",
	FALSE, /* not a construct property, ignored */
        G_PARAM_READWRITE));

   g_object_class_install_property (gobject_class, PROP_FULL_MODE,
      g_param_spec_boolean (
        "full-mode",
        "ICE full mode",
        "Whether agent runs in ICE full mode",
	TRUE, /* use full mode by default */
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  /* install signals */

  /* signature: void cb(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer self) */
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

  /* signature: void cb(NiceAgent *agent, gpointer self) */
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

 /* signature: void cb(NiceAgent *agent, guint stream_id, guint component_id, 
                gchar *lfoundation, gchar* rfoundation, gpointer self) */
  signals[SIGNAL_NEW_SELECTED_PAIR] =
      g_signal_new (
          "new-selected-pair",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT_STRING_STRING,
          G_TYPE_NONE,
          4,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING,
          G_TYPE_INVALID);

 /* signature: void cb(NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation) */
  signals[SIGNAL_NEW_CANDIDATE] =
      g_signal_new (
          "new-candidate",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT_STRING,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING,
          G_TYPE_INVALID);

  /* signature: void cb(NiceAgent *agent, guint stream_id, gpointer self) */
  signals[SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED] =
      g_signal_new (
          "initial-binding-request-received",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT,
          G_TYPE_NONE,
          1,
          G_TYPE_UINT,
          G_TYPE_INVALID);

}


static void
nice_agent_init (NiceAgent *agent)
{
  agent->next_candidate_id = 1;
  agent->next_stream_id = 1;

  /* set defaults; not construct params, so set here */
  g_assert (agent->stun_server_port != IPPORT_STUN);
  g_assert (agent->turn_server_port != IPPORT_STUN);
  agent->stun_server_port = IPPORT_STUN;
  agent->turn_server_port = IPPORT_STUN;
  agent->controlling_mode = TRUE;

  agent->discovery_list = NULL;
  agent->discovery_unsched_items = 0;
  agent->discovery_timer_id = 0;
  agent->conncheck_timer_id = 0;

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
      break;

    case PROP_STUN_SERVER_PORT:
      g_value_set_uint (value, agent->stun_server_port);
      break;

    case PROP_TURN_SERVER:
      g_value_set_string (value, agent->turn_server_ip);
      break;

    case PROP_TURN_SERVER_PORT:
      g_value_set_uint (value, agent->turn_server_port);
      break;

    case PROP_CONTROLLING_MODE:
      g_value_set_boolean (value, agent->controlling_mode);
      break;

    case PROP_FULL_MODE:
      g_value_set_boolean (value, agent->full_mode);
      break;

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

    case PROP_CONTROLLING_MODE:
      agent->controlling_mode = g_value_get_boolean (value);
      break;

    case PROP_FULL_MODE:
      agent->full_mode = g_value_get_boolean (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

void agent_signal_gathering_done (NiceAgent *agent)
{
  g_signal_emit (agent, signals[SIGNAL_CANDIDATE_GATHERING_DONE], 0);
}

void agent_signal_initial_binding_request_received (NiceAgent *agent, Stream *stream)
{
  if (stream->initial_binding_request_received != TRUE) {
    stream->initial_binding_request_received = TRUE;
    g_signal_emit (agent, signals[SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED], 0, stream->id);
  }
}

void agent_signal_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, const gchar *local_foundation, const gchar *remote_foundation)
{
  Component *component;

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return;

  g_signal_emit (agent, signals[SIGNAL_NEW_SELECTED_PAIR], 0, 
		 stream_id, component_id,
		 local_foundation, remote_foundation);
}

void agent_signal_new_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  g_signal_emit (agent, signals[SIGNAL_NEW_CANDIDATE], 0, 
		 candidate->stream_id, 
		 candidate->component_id, 
		 candidate->foundation);
}

void agent_signal_component_state_change (NiceAgent *agent, guint stream_id, guint component_id, NiceComponentState state)
{
  Component *component;

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return;

  if (component->state != state && state < NICE_COMPONENT_STATE_LAST) {
    g_debug ("stream %u component %u state change %u -> %u.",
	     stream_id, component_id, component->state, state);
    component->state = state;

    g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
		   stream_id, component_id, component->state);
  }
}

#if 0
static void priv_signal_component_state_connecting (NiceAgent *agent, guint stream_id, guint component_id)
{
  Component *component;

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return;

  if (component->state != NICE_COMPONENT_STATE_CONNECTING) {
    component->state = NICE_COMPONENT_STATE_CONNECTING;

    g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
		   stream_id, component_id, component->state);
  }
}
#endif

/**
 * nice_agent_add_stream:
 *  @agent: a NiceAgent
 *  @n_components: number of components
 *
 * Add a data stream to @agent.
 *
 * Returns: the ID of the new stream, 0 on failure
 **/
guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components)
{
  Stream *stream;
  GSList *i;

  g_assert (n_components == 1);

  /* XXX: make memory-allocation safe */

  if (!agent->streams) {
    /* note: this contains a Y2038 issue */
    agent->next_check_tv.tv_sec = 
      agent->next_check_tv.tv_usec = (long)-1;
  }

  stream = stream_new ();
  stream->id = agent->next_stream_id++;
  /* note: generate ufrag/pwd for the stream (see ICE ID-15 15.4) */
  nice_rng_generate_bytes_print (agent->rng, NICE_STREAM_MAX_UFRAG_LEN, stream->local_ufrag);
  nice_rng_generate_bytes_print (agent->rng, NICE_STREAM_MAX_PWD_LEN, stream->local_password);

  agent->streams = g_slist_append (agent->streams, stream);

  g_debug ("In %s mode, starting candidate gathering.", agent->full_mode ? "ICE-FULL" : "ICE-LITE");

  /* generate a local host candidate for each local address */

  for (i = agent->local_addresses; i; i = i->next)
    {
      NiceAddress *addr = i->data;
      CandidateDiscovery *cand;
      NiceCandidate *host_candidate;

      /* XXX: not multi-component ready */
      host_candidate = discovery_add_local_host_candidate (agent, stream->id,
							   stream->component->id, addr);
      
      if (host_candidate &&
	  agent->full_mode &&
	  agent->stun_server_ip) {

	/* XXX: need to check for redundant candidates? -> not yet,
	 *  this is done later on */
	
	cand = g_slice_new0 (CandidateDiscovery);
	if (cand) {
	  cand->type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
	  cand->socket = host_candidate->sockptr->fileno;
	  cand->nicesock = host_candidate->sockptr;
	  cand->server_addr = agent->stun_server_ip;
	  cand->interface = addr;
	  cand->stream = stream;
	  /* XXX: not multi-component ready */
	  cand->component = stream->component;
	  cand->agent = agent;
	  g_debug ("Adding new srv-rflx candidate %p\n", cand);
	  agent->discovery_list = g_slist_append (agent->discovery_list, cand);
	  ++agent->discovery_unsched_items;
	}
	else {
	  /* note: memory allocation failure, return error */
	  stream->id = 0;
	  break;
	}
      }
    }

  /* step: attach the newly created sockets to the mainloop
   *       context */
  if (agent->main_context_set)
    priv_attach_new_stream (agent, stream);

  /* note: no async discoveries pending, signal that we are ready */
  if (agent->discovery_unsched_items == 0)
    agent_signal_gathering_done (agent);
  else if (agent->discovery_list)
    discovery_schedule (agent);

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

  stream = agent_find_stream (agent, stream_id);

  if (!stream)
    return;

  /* note: remove items with matching stream_ids from both lists */
  conn_check_prune_stream (agent, stream_id);
  discovery_prune_stream (agent, stream_id);

  /* remove the stream itself */
  priv_deattach_stream (stream);
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

  /* XXX: dear compiler, these are for you: */
  (void)username; (void)password; (void)priority;

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return;

  candidate = nice_candidate_new (type);

  candidate->stream_id = stream_id;
  candidate->component_id = component_id;

  candidate->type = type;
  if (addr)
    candidate->addr = *addr;
  if (related_addr)
    candidate->base_addr = *related_addr;

  candidate->transport = transport;

  if (username)
    candidate->username = g_strdup (username);
  if (password)
    candidate->password = g_strdup (password);

  if (foundation)
    candidate->foundation = g_strdup (foundation);

  component->remote_candidates = g_slist_append (component->remote_candidates,
      candidate);

  /* XXX: may be called before candidate-gathering-done is signalled,
   *      make sure this is handled correctly! */

  conn_check_add_for_candidate (agent, stream_id, component, candidate);
}

/**
 * Sets the remote credentials for stream 'stream_id'.
 *
 * Note: stream credentials do not override per-candidate 
 *       credentials if set
 *
 * @agent: a NiceAgent
 * @stream_id: identifier returnedby nice_agent_add_stream()
 * @ufrag: NULL-terminated string containing an ICE username fragment
 * @pwd: NULL-terminated string containing an ICE password
 *
 * @return TRUE on success
 */
gboolean
nice_agent_set_remote_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar *ufrag, const gchar *pwd)
{
  Stream *stream;

  stream = agent_find_stream (agent, stream_id);
  /* note: oddly enough, ufrag and pwd can be empty strings */
  if (stream && ufrag && pwd) {

    strncpy (stream->remote_ufrag, ufrag, NICE_STREAM_MAX_UFRAG_LEN);
    strncpy (stream->remote_password, pwd, NICE_STREAM_MAX_PWD_LEN);

    return TRUE;
  }

  return FALSE;
}

/**
 * Gets the local credentials for stream 'stream_id'.
 *
 * @agent: a NiceAgent
 * @stream_id: identifier returnedby nice_agent_add_stream()
 * @ufrag: a pointer to a NULL-terminated string containing 
 *         an ICE username fragment [OUT]
 * @pwd: a pointer to a NULL-terminated string containing an ICE
 *         password [OUT]
 *
 * @return TRUE on success
 */
gboolean
nice_agent_get_local_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar **ufrag, const gchar **pwd)
{
  Stream *stream = agent_find_stream (agent, stream_id);

  if (stream == NULL)
    return FALSE;

  if (!ufrag || !pwd)
    return FALSE;

  *ufrag = stream->local_ufrag;
  *pwd = stream->local_password;

  return TRUE;
}

/**
 * nice_agent_add_remote_candidate
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream the candidate is for
 *  @component_id: the ID of the component the candidate is for
 *  @type: the type of the new candidate
 *  @addr: the new candidate's IP address
 *  @port: the new candidate's port
 *  @username: the new candidate's username (XXX: candidates don't have usernames)
 *  @password: the new candidate's password (XXX: candidates don't have usernames)
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
     candidate, see below set_remote_candidates() */
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
 
 conn_check_schedule_next (agent);
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

static guint
_nice_agent_recv (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceUDPSocket *udp_socket,
  guint buf_len,
  gchar *buf)
{
  NiceAddress from;
  guint len;

  g_debug ("Packet received on local socket %d.", udp_socket->fileno);

  len = nice_udp_socket_recv (udp_socket, &from,
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

  /* step: check for a RTP fingerprint 
   *   - XXX: should use a two-phase check, first a lightweight check,
   *     and then full validation */
  if ((buf[0] & 0xc0) == 0x80)
    {
      /* looks like RTP */
      return len;
    }
  /* step: validate using the new STUN API */
  /*    - XXX: old check '((buf[0] & 0xc0) == 0)' */
  else if (stun_validate ((uint8_t*)buf, len) > 0) 
    {
      conn_check_handle_inbound_stun (agent, stream, component, &from, buf, len);
    }
  else 
    {
      /* not RTP nor STUN, pass to client */
      return len;
    }

  /* code using the old SUTN API */
#if 0
    {
      /* looks like a STUN message (connectivity check) */
      /* connectivity checks are described in ICE-13 §7. */

      /* XXX: still using the old STUN API below 
       *   - with new API, call stun_bind_process() or some such
       *     to process the incoming STUN packet */

      StunMessage *msg;
      
      msg = stun_message_unpack (len, buf);
      
      if (msg != NULL)
	{
	  conn_check_handle_inbound_stun_old (agent, stream, component, candidate, from, msg);
	  stun_message_free (msg);
	}
    }
#endif

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
 * Receive data on a particular component.
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

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return 0;

  FD_ZERO (&fds);

  for (i = component->sockets; i; i = i->next)
    {
      NiceUDPSocket *sockptr = i->data;

      FD_SET (sockptr->fileno, &fds);
      max_fd = MAX (sockptr->fileno, max_fd);
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
                NiceUDPSocket *socket;

		socket = component_find_udp_socket_by_fd (component, j);
                g_assert (socket);

                len = _nice_agent_recv (agent, stream, component, socket,
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
  NiceUDPSocket *socket;
  Stream *stream;
  Component *component;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return 0;

  socket = component_find_udp_socket_by_fd (component, sock);
  g_assert (socket);

  /* XXX: not multi-component ready */
  return _nice_agent_recv (agent, stream, stream->component,
			   socket, buf_len, buf);
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
      /* XXX: not multi-component ready */
      Component *component = stream->component;

      for (j = component->sockets; j; j = j->next)
        {
          NiceUDPSocket *sockptr = j->data;

          FD_SET (sockptr->fileno, &fds);
          max_fd = MAX (sockptr->fileno, max_fd);
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
            NiceUDPSocket *socket;
            Stream *stream = NULL;
            gchar buf[MAX_STUN_DATAGRAM_PAYLOAD];
            guint len;

            for (i = agent->streams; i; i = i->next)
              {
                Stream *s = i->data;
                Component *c = s->component;

		socket = component_find_udp_socket_by_fd (c, j);

                if (socket != NULL) {
		  stream = s;
                  break;
		}
              }
	    
            if (socket == NULL || stream == NULL)
              break;

	    /* XXX: not multi-component ready */
            len = _nice_agent_recv (agent, stream, stream->component,
				    socket, MAX_STUN_DATAGRAM_PAYLOAD, buf);

            if (len && func != NULL)
              func (agent, stream->id, stream->component->id, len, buf,
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

  /* XXX: dear compiler, these are for you: */
  (void)component_id;

  stream = agent_find_stream (agent, stream_id);

  /* XXX: not multi-component ready */
  component = stream->component;

  if (component->selected_pair.local != NULL)
    {
      NiceUDPSocket *sock;
      NiceAddress *addr;

#if 1
      g_debug ("s%d:%d: sending %d bytes to %08x:%d", stream_id, component_id,
          len, component->selected_pair.remote->addr.addr_ipv4, component->selected_pair.remote->addr.port);
#endif

      sock = component->selected_pair.local->sockptr;
      addr = &component->selected_pair.remote->addr;
      nice_udp_socket_send (sock, addr, len, buf);
    }
}


/**
 * nice_agent_get_local_candidates:
 *  @agent: A NiceAgent
 *
 * The caller owns the returned GSList but not the candidates contained within
 * it. To get full results, the client should wait for the
 * 'candidates-gathering-done' signal.
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

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
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

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
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

  /* step: free resources for the binding discovery timers */
  discovery_free (agent);
  g_assert (agent->discovery_list == NULL);

  /* step: free resources for the connectivity check timers */
  conn_check_free (agent);
  g_assert (agent->conncheck_list == NULL);

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
  g_free (agent->turn_server_ip);
  agent->turn_server_ip = NULL;

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
  NiceUDPSocket *socket;
};


static IOCtx *
io_ctx_new (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceUDPSocket *socket)
{
  IOCtx *ctx;

  ctx = g_slice_new0 (IOCtx);
  if (ctx) {
    ctx->agent = agent;
    ctx->stream = stream;
    ctx->component = component;
    ctx->socket = socket;
  }
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
  gchar buf[MAX_STUN_DATAGRAM_PAYLOAD];
  guint len;

  /* XXX: dear compiler, these are for you: */
  (void)source;

  len = _nice_agent_recv (agent, stream, component, ctx->socket, 
			  MAX_STUN_DATAGRAM_PAYLOAD, buf);

  if (len > 0)
    agent->read_func (agent, stream->id, component->id,
        len, buf, agent->read_func_data);

  return TRUE;
}

/**
 * Attaches socket handles of 'stream' to the main eventloop
 * context.
 *
 * @pre agent->main_context_set == TRUE
 */
static gboolean priv_attach_new_stream (NiceAgent *agent, Stream *stream)
{
  GSList *j;
  /* XXX: not multi-component ready */
  Component *component = stream->component;

  for (j = component->sockets; j; j = j->next) {
    NiceUDPSocket *udp_socket = j->data;
    GIOChannel *io;
    GSource *source;
    IOCtx *ctx;
    
    io = g_io_channel_unix_new (udp_socket->fileno);
    source = g_io_create_watch (io, G_IO_IN);
    ctx = io_ctx_new (agent, stream, component, udp_socket);
    g_source_set_callback (source, (GSourceFunc) nice_agent_g_source_cb,
			   ctx, (GDestroyNotify) io_ctx_free);
    g_debug ("Attach source %p (stream %u).", source, stream->id);
    g_source_attach (source, NULL);
    component->gsources = g_slist_append (component->gsources, source);
    if (!component->gsources) {
      g_source_destroy (source);
      return FALSE;
    }
  }

  return TRUE;
}

/**
 * Detaches socket handles of 'stream' from the main eventloop
 * context.
 *
 * @pre agent->main_context_set == TRUE
 */
static void priv_deattach_stream (Stream *stream)
{
  GSList *j;
  /* XXX: not multi-component ready */
  Component *component = stream->component;

  for (j = component->gsources; j; j = j->next) {
    GSource *source = j->data;
    g_debug ("Detach source %p (stream %u).", source, stream->id);
    g_source_destroy (source);
  }

  g_slist_free (component->gsources),
    component->gsources = NULL;
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

  /* XXX: when sockets are not yet created, or new streams are added,
   *      the mainloop integration won't then work anymore! */
  
  /* attach candidates */

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    gboolean res = priv_attach_new_stream (agent, stream);
    if (!res)
      return FALSE;
  }
  
  agent->main_context = ctx;
  agent->main_context_set = TRUE;
  agent->read_func = func;
  agent->read_func_data = data;

  return TRUE;
}
