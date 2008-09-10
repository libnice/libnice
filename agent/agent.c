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

/**
 * @file agent.c
 * @brief ICE agent API implementation
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <errno.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include "debug.h"

#include "udp.h"
#include "udp-bsd.h"
#include "udp-turn.h"
#include "candidate.h"
#include "component.h"
#include "conncheck.h"
#include "discovery.h"
#include "agent.h"
#include "agent-priv.h"
#include "agent-signals-marshal.h"

#include "stream.h"

/* This is the max size of a UDP packet
 * will it work tcp relaying??
 */
#define MAX_BUFFER_SIZE 65536
#define DEFAULT_STUN_PORT  3478


G_DEFINE_TYPE (NiceAgent, nice_agent, G_TYPE_OBJECT);

enum
{
  PROP_COMPATIBILITY = 1,
  PROP_MAIN_CONTEXT,
  PROP_STUN_SERVER,
  PROP_STUN_SERVER_PORT,
  PROP_CONTROLLING_MODE,
  PROP_FULL_MODE,
  PROP_STUN_PACING_TIMER,
  PROP_MAX_CONNECTIVITY_CHECKS
};


enum
{
  SIGNAL_COMPONENT_STATE_CHANGED,
  SIGNAL_CANDIDATE_GATHERING_DONE,
  SIGNAL_NEW_SELECTED_PAIR,
  SIGNAL_NEW_CANDIDATE,
  SIGNAL_NEW_REMOTE_CANDIDATE,
  SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED,
  N_SIGNALS,
};


static guint signals[N_SIGNALS];

static gboolean priv_attach_stream_component (NiceAgent *agent,
    Stream *stream,
    Component *component);
static void priv_detach_stream_component (Stream *stream, Component *component);

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
  Component *c;

  s = agent_find_stream (agent, stream_id);

  if (s == NULL)
    return FALSE;

  c = stream_find_component_by_id (s, component_id);

  if (c == NULL)
    return FALSE;

  if (stream)
    *stream = s;

  if (component)
    *component = c;

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

  g_object_class_install_property (gobject_class, PROP_MAIN_CONTEXT,
      g_param_spec_pointer (
         "main-context",
         "The GMainContext to use for timeouts",
         "The GMainContext to use for timeouts",
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_COMPATIBILITY,
      g_param_spec_uint (
         "compatibility",
         "ICE specification compatibility",
         "The compatibility mode for the agent",
         NICE_COMPATIBILITY_ID19, NICE_COMPATIBILITY_LAST,
         NICE_COMPATIBILITY_ID19,
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
	1, /* not a construct property, ignored */
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

  g_object_class_install_property (gobject_class, PROP_STUN_PACING_TIMER,
      g_param_spec_uint (
        "stun-pacing-timer",
        "STUN pacing timer",
        "Timer 'Ta' (msecs) used in the IETF ICE specification for pacing candidate gathering and sending of connectivity checks",
        1, 0xffffffff, 
	NICE_AGENT_TIMER_TA_DEFAULT,
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  /* note: according to spec recommendation in sect 5.7.3 (ID-19) */
  g_object_class_install_property (gobject_class, PROP_MAX_CONNECTIVITY_CHECKS,
      g_param_spec_uint (
        "max-connectivity-checks",
        "Maximum number of connectivity checks",
        "Upper limit for the total number of connectivity checks performed",
        0, 0xffffffff, 
	0, /* default set in init */
        G_PARAM_READWRITE));

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

 /* signature: void cb(NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation) */
  signals[SIGNAL_NEW_REMOTE_CANDIDATE] =
      g_signal_new (
          "new-remote-candidate",
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

static void priv_generate_tie_breaker (NiceAgent *agent) 
{
  nice_rng_generate_bytes (agent->rng, 8, (gchar*)&agent->tie_breaker);
}

static void
nice_agent_init (NiceAgent *agent)
{
  agent->next_candidate_id = 1;
  agent->next_stream_id = 1;

  /* set defaults; not construct params, so set here */
  agent->stun_server_port = DEFAULT_STUN_PORT;
  agent->controlling_mode = TRUE;
  agent->max_conn_checks = NICE_AGENT_MAX_CONNECTIVITY_CHECKS_DEFAULT;

  agent->discovery_list = NULL;
  agent->discovery_unsched_items = 0;
  agent->discovery_timer_id = 0;
  agent->conncheck_timer_id = 0;
  agent->keepalive_timer_id = 0;
  agent->compatibility = NICE_COMPATIBILITY_ID19;

  stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_3489BIS,
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
      STUN_AGENT_USAGE_USE_FINGERPRINT);

  nice_udp_bsd_socket_factory_init (&agent->udp_socket_factory);
  nice_udp_turn_socket_factory_init (&agent->relay_socket_factory);

  agent->rng = nice_rng_new ();
  priv_generate_tie_breaker (agent);

  g_static_rec_mutex_init (&agent->mutex);
}


/**
 * nice_agent_new:
 *
 * Create a new NiceAgent.
 *
 * Returns: the new agent
 **/
NICEAPI_EXPORT NiceAgent *
nice_agent_new (GMainContext *ctx, NiceCompatibility compat)
{
  NiceAgent *agent = g_object_new (NICE_TYPE_AGENT,
      "compatibility", compat,
      "main-context", ctx,
      NULL);

  return agent;
}


static void
nice_agent_get_property (
  GObject *object,
  guint property_id,
  GValue *value,
  GParamSpec *pspec)
{
  NiceAgent *agent = NICE_AGENT (object);

  g_static_rec_mutex_lock (&agent->mutex);

  switch (property_id)
    {
    case PROP_MAIN_CONTEXT:
      g_value_set_pointer (value, agent->main_context);
      break;

    case PROP_COMPATIBILITY:
      g_value_set_uint (value, agent->compatibility);
      break;

    case PROP_STUN_SERVER:
      g_value_set_string (value, agent->stun_server_ip);
      break;

    case PROP_STUN_SERVER_PORT:
      g_value_set_uint (value, agent->stun_server_port);
      break;

    case PROP_CONTROLLING_MODE:
      g_value_set_boolean (value, agent->controlling_mode);
      break;

    case PROP_FULL_MODE:
      g_value_set_boolean (value, agent->full_mode);
      break;

    case PROP_STUN_PACING_TIMER:
      g_value_set_uint (value, agent->timer_ta);
      break;

    case PROP_MAX_CONNECTIVITY_CHECKS:
      g_value_set_uint (value, agent->max_conn_checks);
      /* XXX: should we prune the list of already existing checks? */
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  g_static_rec_mutex_unlock (&agent->mutex);
}


static void
nice_agent_set_property (
  GObject *object,
  guint property_id,
  const GValue *value,
  GParamSpec *pspec)
{
  NiceAgent *agent = NICE_AGENT (object);

  g_static_rec_mutex_lock (&agent->mutex);

  switch (property_id)
    {
    case PROP_MAIN_CONTEXT:
      agent->main_context = g_value_get_pointer (value);
      break;

    case PROP_COMPATIBILITY:
      agent->compatibility = g_value_get_uint (value);
      if (agent->compatibility == NICE_COMPATIBILITY_ID19) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_3489BIS,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_USE_FINGERPRINT);
      } else if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
      } else if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_FORCE_VALIDATER);
      }

      break;

    case PROP_STUN_SERVER:
      agent->stun_server_ip = g_value_dup_string (value);
      break;

    case PROP_STUN_SERVER_PORT:
      agent->stun_server_port = g_value_get_uint (value);
      break;

    case PROP_CONTROLLING_MODE:
      agent->controlling_mode = g_value_get_boolean (value);
      break;

    case PROP_FULL_MODE:
      agent->full_mode = g_value_get_boolean (value);
      break;

    case PROP_STUN_PACING_TIMER:
      agent->timer_ta = g_value_get_uint (value);
      break;

    case PROP_MAX_CONNECTIVITY_CHECKS:
      agent->max_conn_checks = g_value_get_uint (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  g_static_rec_mutex_unlock (&agent->mutex);

}

void agent_gathering_done (NiceAgent *agent)
{

  GSList *i, *j, *k, *l, *m;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *component = j->data;

      for (k = component->local_candidates; k; k = k->next) {
        NiceCandidate *local_candidate = k->data;

        for (l = component->remote_candidates; l; l = l->next) {
          NiceCandidate *remote_candidate = l->data;

          for (m = stream->conncheck_list; m; m = m->next) {
            CandidateCheckPair *p = m->data;

            if (p->local == local_candidate && p->remote == remote_candidate)
              break;
          }
          if (m == NULL) {
            conn_check_add_for_candidate (agent, stream->id, component, remote_candidate);
          }
        }
      }
    }
  }

  agent_signal_gathering_done (agent);
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
  gchar *lf_copy;
  gchar *rf_copy;

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return;

  lf_copy = g_strdup (local_foundation);
  rf_copy = g_strdup (remote_foundation);


  g_signal_emit (agent, signals[SIGNAL_NEW_SELECTED_PAIR], 0,
      stream_id, component_id, lf_copy, rf_copy);

  g_free (lf_copy);
  g_free (rf_copy);
}

void agent_signal_new_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  g_signal_emit (agent, signals[SIGNAL_NEW_CANDIDATE], 0,
		 candidate->stream_id,
		 candidate->component_id,
		 candidate->foundation);
}

void agent_signal_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  g_signal_emit (agent, signals[SIGNAL_NEW_REMOTE_CANDIDATE], 0, 
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
    nice_debug ("Agent %p : stream %u component %u STATE-CHANGE %u -> %u.", agent,
	     stream_id, component_id, component->state, state);

    component->state = state;

    g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
		   stream_id, component_id, state);
  }
}

guint64
agent_candidate_pair_priority (NiceAgent *agent, NiceCandidate *local, NiceCandidate *remote)
{
  if (agent->controlling_mode)
    return nice_candidate_pair_priority (local->priority, remote->priority);
  else
    return nice_candidate_pair_priority (remote->priority, local->priority);
}

static gboolean
priv_add_new_candidate_discovery (NiceAgent *agent,
    NiceCandidate *host_candidate, NiceAddress server,
    Stream *stream, guint component_id,
    NiceAddress *addr, NiceCandidateType type)
{
  CandidateDiscovery *cdisco;
  GSList *modified_list;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);
  if (cdisco) {
    modified_list = g_slist_append (agent->discovery_list, cdisco);

    if (modified_list) {
      cdisco->type = type;
      cdisco->socket = host_candidate->sockptr->fileno;
      cdisco->nicesock = host_candidate->sockptr;
      cdisco->server = server;
      cdisco->interface = addr;
      cdisco->stream = stream;
      cdisco->component = stream_find_component_by_id (stream, component_id);
      cdisco->agent = agent;
      nice_debug ("Agent %p : Adding new srv-rflx candidate discovery %p\n", agent, cdisco);
      agent->discovery_list = modified_list;
      ++agent->discovery_unsched_items;
    }

    return TRUE;
  }

  return FALSE;
}


/**
 * nice_agent_add_stream:
 *  @agent: a NiceAgent
 *  @n_components: number of components
 *
 * Add a data stream to @agent.
 *
 * @pre local addresses must be set with nice_agent_add_local_address()
 *
 * Returns: the ID of the new stream, 0 on failure
 **/
NICEAPI_EXPORT guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components)
{
  Stream *stream;
  GSList *modified_list = NULL;
  guint ret = 0;

  g_static_rec_mutex_lock (&agent->mutex);

  if (!agent->local_addresses) {
    g_warn_if_fail(agent->local_addresses);
    goto done;
  }

  stream = stream_new (n_components);
  if (stream) {
    modified_list = g_slist_append (agent->streams, stream);
    if (modified_list) {
      stream->id = agent->next_stream_id++;
      nice_debug ("Agent %p : allocating stream id %u (%p)", agent, stream->id, stream);

      stream_initialize_credentials (stream, agent->rng);

      agent->streams = modified_list;
    }
    else
      stream_free (stream);
  }

  ret = stream->id;

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}


NICEAPI_EXPORT void nice_agent_set_relay_info(NiceAgent *agent,
    guint stream_id, guint component_id,
    const gchar *server_ip, guint server_port,
    const gchar *username, const gchar *password,
    gboolean long_term_credentials)
{

  Component *component = NULL;

  g_static_rec_mutex_lock (&agent->mutex);

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    nice_address_init (&component->turn_server);

    if (nice_address_set_from_string (&component->turn_server, server_ip)) {
      nice_address_set_port (&component->turn_server, server_port);
    }


    g_free (component->turn_username);
    component->turn_username = g_strdup (username);

    g_free (component->turn_password);
    component->turn_password = g_strdup (password);

    component->turn_long_term = long_term_credentials;

  }
  g_static_rec_mutex_unlock (&agent->mutex);
}


/**
 * nice_agent_gather_candidates:
 *
 * start the candidate gathering process
 */

NICEAPI_EXPORT void
nice_agent_gather_candidates (
  NiceAgent *agent,
  guint stream_id)
{
  guint n;
  GSList *i;
  Stream *stream;

  g_static_rec_mutex_lock (&agent->mutex);

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    goto done;
  }

  nice_debug ("Agent %p : In %s mode, starting candidate gathering.", agent, agent->full_mode ? "ICE-FULL" : "ICE-LITE");

  /* generate a local host candidate for each local address */

  for (i = agent->local_addresses; i; i = i->next)
    {
      NiceAddress *addr = i->data;
      NiceCandidate *host_candidate;

      for (n = 0; n < stream->n_components; n++) {
        Component *component = stream_find_component_by_id (stream, n + 1);
	host_candidate = discovery_add_local_host_candidate (agent, stream->id,
							     n + 1, addr);

	if (!host_candidate) {
          g_error ("No host candidate??");
	  break;
	}

	if (agent->full_mode &&
	    agent->stun_server_ip) {
          NiceAddress stun_server;
          if (nice_address_set_from_string (&stun_server,  agent->stun_server_ip)) {
            nice_address_set_port (&stun_server, agent->stun_server_port);

            gboolean res =
                priv_add_new_candidate_discovery (agent,
                    host_candidate,
                    stun_server,
                    stream,
                    n + 1 /* component-id */,
                    addr,
                    NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);

            if (res != TRUE) {
              /* note: memory allocation failure, return error */
              g_error ("Memory allocation failure?");
            }
          }
	}
	if (agent->full_mode &&
            component && nice_address_is_valid (&component->turn_server)) {

	  gboolean res =
	    priv_add_new_candidate_discovery (agent,
                host_candidate,
                component->turn_server,
                stream,
                n + 1 /* component-id */,
                addr,
                NICE_CANDIDATE_TYPE_RELAYED);

	  if (res != TRUE) {
	    /* note: memory allocation failure, return error */
	    g_error ("Memory allocation failure?");
	  }
	}
      }
    }


  /* note: no async discoveries pending, signal that we are ready */
  if (agent->discovery_unsched_items == 0) {
    agent_gathering_done (agent);
  } else {
    g_assert (agent->discovery_list);
    discovery_schedule (agent);
  }

 done:

  g_static_rec_mutex_unlock (&agent->mutex);
}

static void priv_remove_keepalive_timer (NiceAgent *agent)
{
  if (agent->keepalive_timer_id) {
    g_source_remove (agent->keepalive_timer_id),
      agent->keepalive_timer_id = 0;
  }
}

/**
 * nice_agent_remove_stream:
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream to remove
 **/
NICEAPI_EXPORT void
nice_agent_remove_stream (
  NiceAgent *agent,
  guint stream_id)
{
  /* note that streams/candidates can be in use by other threads */

  Stream *stream;
  GSList *i;

  g_static_rec_mutex_lock (&agent->mutex);
  stream = agent_find_stream (agent, stream_id);

  if (!stream) {
    goto done;
  }

  /* note: remove items with matching stream_ids from both lists */
  conn_check_prune_stream (agent, stream);
  discovery_prune_stream (agent, stream_id);

  /* remove the stream itself */
  for (i = stream->components; i; i = i->next) {
    priv_detach_stream_component (stream, (Component *) i->data);
  }

  agent->streams = g_slist_remove (agent->streams, stream);
  stream_free (stream);

  if (!agent->streams)
    priv_remove_keepalive_timer (agent);

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
}

/**
 * nice_agent_add_local_address:
 *  @agent: A NiceAgent
 *  @addr: the address of a local IP interface
 *
 * Inform the agent of the presence of an address that a local 
 * network interface is bound to.
 *
 * @return FALSE on fatal (memory allocation) errors
 **/
NICEAPI_EXPORT gboolean
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr)
{
  NiceAddress *dup;
  GSList *modified_list;
  gboolean ret = FALSE;

  g_static_rec_mutex_lock (&agent->mutex);

  dup = nice_address_dup (addr);
  nice_address_set_port (dup, 0);
  modified_list = g_slist_append (agent->local_addresses, dup);
  if (modified_list) {
    agent->local_addresses = modified_list;

    ret = TRUE;
    goto done;
  }

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

/**
 * Adds a new, or updates an existing, remote candidate.
 *
 * @return TRUE if candidate was succesfully added or 
 *         update, otherwise FALSE
 */
static gboolean priv_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  const NiceAddress *addr,
  const NiceAddress *base_addr,
  NiceCandidateTransport transport,
  guint32 priority,
  const gchar *username,
  const gchar *password,
  const gchar *foundation)
{
  Component *component;
  NiceCandidate *candidate;
  gchar *username_dup = NULL, *password_dup = NULL;
  gboolean error_flag = FALSE;

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return FALSE;

  /* step: check whether the candidate already exists */
  candidate = component_find_remote_candidate(component, addr, transport);
  if (candidate) {
    nice_debug ("Agent %p : Update existing remote candidate %p.", agent, candidate);
    /* case 1: an existing candidate, update the attributes */
    candidate->type = type;
    if (base_addr)
      candidate->base_addr = *base_addr;
    candidate->priority = priority;
    if (foundation)
      strncpy(candidate->foundation, foundation, NICE_CANDIDATE_MAX_FOUNDATION);
    /* note: username and password must remain the same during
     *       a session; see sect 9.1.2 in ICE ID-19 */
    if (conn_check_add_for_candidate (agent, stream_id, component, candidate) < 0)
      error_flag = TRUE;
  }
  else {
    /* case 2: add a new candidate */
    if (username)
      username_dup = g_strdup (username);
    if (password) 
      password_dup = g_strdup (password);

    candidate = nice_candidate_new (type);
    if (candidate) {
      GSList *modified_list = g_slist_append (component->remote_candidates, candidate);
      if (modified_list) {
	component->remote_candidates = modified_list;
	
	candidate->stream_id = stream_id;
	candidate->component_id = component_id;

	candidate->type = type;
	if (addr)
	  candidate->addr = *addr;
#ifndef NDEBUG
	{
	  gchar tmpbuf[INET6_ADDRSTRLEN];
	  nice_address_to_string (addr, tmpbuf);
	  nice_debug ("Agent %p : Adding remote candidate with addr [%s]:%u.", agent, tmpbuf,
		   nice_address_get_port (addr));
	}
#endif
	
	if (base_addr)
	  candidate->base_addr = *base_addr;
	
	candidate->transport = transport;
	candidate->priority = priority;
	candidate->username = username_dup;
	candidate->password = password_dup;
	
	if (foundation)
	  g_strlcpy (candidate->foundation, foundation, NICE_CANDIDATE_MAX_FOUNDATION);

	if (conn_check_add_for_candidate (agent, stream_id, component, candidate) < 0)
	  error_flag = TRUE;
      }
      else /* memory alloc error: list insert */
	error_flag = TRUE;
    }
    else /* memory alloc error: candidate creation */
      error_flag = TRUE;
  }  

  if (error_flag) {
    if (candidate) 
      nice_candidate_free (candidate);
    g_free (username_dup);
    g_free (password_dup);
    return FALSE;
  }

  return TRUE;
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
 *    (length must be between 22 and 256 chars)
 * @pwd: NULL-terminated string containing an ICE password
 *    (length must be between 4 and 256 chars)
 *
 * @return TRUE on success
 */
NICEAPI_EXPORT gboolean
nice_agent_set_remote_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar *ufrag, const gchar *pwd)
{
  Stream *stream;
  gboolean ret = FALSE;

  g_static_rec_mutex_lock (&agent->mutex);

  stream = agent_find_stream (agent, stream_id);
  /* note: oddly enough, ufrag and pwd can be empty strings */
  if (stream && ufrag && pwd) {

    g_strlcpy (stream->remote_ufrag, ufrag, NICE_STREAM_MAX_UFRAG);
    g_strlcpy (stream->remote_password, pwd, NICE_STREAM_MAX_PWD);

    ret = TRUE;
    goto done;
  }

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
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
NICEAPI_EXPORT gboolean
nice_agent_get_local_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar **ufrag, const gchar **pwd)
{
  Stream *stream;
  gboolean ret = TRUE;

  g_static_rec_mutex_lock (&agent->mutex);

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    goto done;
  }

  if (!ufrag || !pwd) {
    goto done;
  }

  *ufrag = stream->local_ufrag;
  *pwd = stream->local_password;
  ret = TRUE;

 done:

  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

/**
 * nice_agent_add_remote_candidate
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream the candidate is for
 *  @component_id: the ID of the component the candidate is for
 *  @type: the type of the new candidate
 *  @addr: the new candidate's IP address
 *  @username: the new candidate's username (XXX: candidates don't have usernames)
 *  @password: the new candidate's password (XXX: candidates don't have usernames)
 *
 * Add a candidate our peer has informed us about to the agent's list.
 *
 * Note: NICE_AGENT_MAX_REMOTE_CANDIDATES is the absolute
 *       maximum limit for remote candidates
 * @return FALSE on fatal (memory alloc) errors
 **/
NICEAPI_EXPORT gboolean
nice_agent_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  NiceAddress *addr,
  const gchar *username,
  const gchar *password)
{

  /* XXX: to be deprecated */

  g_static_rec_mutex_lock (&agent->mutex);

  /* XXX: should we allow use of this method without an 
   *      initial call to nice_agent_set_remote_candidates()
   *      with an empty set? */

  gboolean ret =
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

  /* XXX/later: for each component, generate a new check with the new
     candidate, see below set_remote_candidates() */


  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

/**
 * nice_agent_set_remote_candidates
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream the candidate is for
 *  @component_id: the ID of the component the candidate is for
 *  @candidates: a list of NiceCandidate items describing the candidates
 *
 * Sets the remote candidates for a component of a stream. Replaces
 * any existing remote candidates.
 *
 * Note: NICE_AGENT_MAX_REMOTE_CANDIDATES is the absolute
 *       maximum limit for remote candidates
 *
 * @return number of candidates added, negative on fatal (memory
 *         allocs) errors
 **/
NICEAPI_EXPORT int
nice_agent_set_remote_candidates (NiceAgent *agent, guint stream_id, guint component_id, const GSList *candidates)
{
  const GSList *i; 
  int added = 0;


  if (agent->discovery_unsched_items > 0)
    return -1;

  g_static_rec_mutex_lock (&agent->mutex);

 for (i = candidates; i && added >= 0; i = i->next) {
   NiceCandidate *d = (NiceCandidate*) i->data;
   gboolean res = 
     priv_add_remote_candidate (agent,
				stream_id,
				component_id,
				d->type,
				&d->addr,
				&d->base_addr,
				d->transport,
				d->priority,
                                d->username,
				d->password,
				d->foundation);
   if (res)
     ++added;
   else 
     added = -1;
 }

 conn_check_remote_candidates_set(agent);

 if (added > 0) {
   gboolean res = conn_check_schedule_next (agent);
   if (res != TRUE)
     nice_debug ("Agent %p : Warning: unable to schedule any conn checks!", agent);
 }

 g_static_rec_mutex_unlock (&agent->mutex);
 return added;
}


/**
 * Reads data from a ready, nonblocking socket attached to an ICE
 * stream component.
 *
 * @return number of octets received, or negative on error
 */
static gint
_nice_agent_recv (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceUDPSocket *udp_socket,
  guint buf_len,
  gchar *buf)
{
  NiceAddress from;
  gint len;

  len = nice_udp_socket_recv (udp_socket, &from,
			      buf_len, buf);

#ifndef NDEBUG
  if (len >= 0) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (&from, tmpbuf);
    nice_debug ("Agent %p : Packet received on local socket %u from [%s]:%u (%u octets).", agent,
             udp_socket->fileno, tmpbuf, nice_address_get_port (&from), len);
  }
#endif

  if (len == 0)
    return 0;

  if ((guint)len > buf_len)
    {
      /* buffer is not big enough to accept this packet */
      /* XXX: test this case */
      return 0;
    }

  if (nice_address_equal (&from, &component->turn_server)) {
    GSList * i = NULL;
    nice_debug ("Agent %p : Packet received from TURN server candidate.", agent);
    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (cand->type == NICE_CANDIDATE_TYPE_RELAYED) {
        len = nice_udp_turn_socket_parse_recv (cand->sockptr, &from, len, buf, &from, buf, len);
      }
    }
  }

  if (!stun_message_validate_buffer_length ((uint8_t *) buf, (size_t) len) ==
      len)
    /* If the retval is no 0, its not a valid stun packet, probably data */
    return len;


  if (conn_check_handle_inbound_stun (agent, stream, component, udp_socket,
          &from, buf, len))
    /* handled STUN message*/
    return 0;

  /* unhandled STUN, pass to client */
  return len;
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
NICEAPI_EXPORT guint
nice_agent_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint buf_len,
  gchar *buf)
{
  gint len = 0;
  fd_set fds;
  guint max_fd = 0;
  gint num_readable;
  GSList *i;
  Stream *stream;
  Component *component;
  guint ret = 0;

  g_static_rec_mutex_lock (&agent->mutex);
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

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

                if (len >= 0) {
                  ret = len;
                  goto done;
                }
              }
        }
    }

  /* note: commented out to avoid compiler warnings 
   *
   * g_assert_not_reached (); */
 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

NICEAPI_EXPORT guint
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
  guint ret = 0;

  g_static_rec_mutex_lock (&agent->mutex);
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  socket = component_find_udp_socket_by_fd (component, sock);
  g_assert (socket);

  ret = _nice_agent_recv (agent, stream, component,
			   socket, buf_len, buf);

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
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
NICEAPI_EXPORT GSList *
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

  g_static_rec_mutex_lock (&agent->mutex);

  FD_ZERO (&fds);

  for (i = agent->streams; i; i = i->next)
    {
      GSList *j, *k;
      Stream *stream = i->data;

      for (k = stream->components; k; k = k->next)
	{
	  Component *component = k->data;

	  for (j = component->sockets; j; j = j->next)
	    {
	      NiceUDPSocket *sockptr = j->data;

	      FD_SET (sockptr->fileno, &fds);
	      max_fd = MAX (sockptr->fileno, max_fd);
	    }
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

  if (num_readable < 1) {
    /* none readable, or error */
    goto done;
  }

  for (j = 0; j <= max_fd; j++)
    if (FD_ISSET (j, &fds))
      {
        if (g_slist_find (other_fds, GUINT_TO_POINTER (j))) {
	  GSList *modified_list = g_slist_append (ret, GUINT_TO_POINTER (j));
	  if (modified_list == NULL) {
	    g_slist_free (ret);
            goto done;
	  }
	  ret = modified_list;
	}
        else
          {
            NiceUDPSocket *socket = NULL;
            Stream *stream = NULL;
	    Component *component = NULL;
            gchar buf[MAX_BUFFER_SIZE];
            guint len;

            for (i = agent->streams; i; i = i->next)
              {
                Stream *s = i->data;
                Component *c = stream_find_component_by_fd (s, j);

		socket = component_find_udp_socket_by_fd (c, j);

                if (socket != NULL) {
		  stream = s;
		  component = c;
                  break;
		}
              }

            if (socket == NULL || stream == NULL || component == NULL)
              break;

            len = _nice_agent_recv (agent, stream, component,
				    socket, MAX_BUFFER_SIZE, buf);

            if (len && func != NULL)
              func (agent, stream->id, component->id, len, buf,
		    data);
          }
      }

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}



/**
 * Sends a data payload over a stream component.
 *
 * @pre component state MUST be NICE_COMPONENT_STATE_READY,
 * or as a special case, in any state if component was
 * in READY state before and was then restarted
 *
 * @return number of bytes sent, or negative error code
 */
NICEAPI_EXPORT gint
nice_agent_send (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  const gchar *buf)
{
  Stream *stream;
  Component *component;
  guint ret = -1;

  g_static_rec_mutex_lock (&agent->mutex);

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  if (component->selected_pair.local != NULL)
    {
      NiceUDPSocket *sock;
      NiceAddress *addr;

#ifndef NDEBUG
      gchar tmpbuf[INET6_ADDRSTRLEN];
      nice_address_to_string (&component->selected_pair.remote->addr, tmpbuf);

      nice_debug ("Agent %p : s%d:%d: sending %d bytes to [%s]:%d", agent, stream_id, component_id,
          len, tmpbuf,
          nice_address_get_port (&component->selected_pair.remote->addr));
#endif

      sock = component->selected_pair.local->sockptr;
      addr = &component->selected_pair.remote->addr;
      nice_udp_socket_send (sock, addr, len, buf);
      component->media_after_tick = TRUE;

      ret = len;
      goto done;
    }

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}


/**
 * nice_agent_get_local_candidates:
 *  @agent: A NiceAgent
 *
 * The caller owns the returned GSList as well as the candidates contained
 * within it. To get full results, the client should wait for the
 * 'candidates-gathering-done' signal.
 *
 * Returns: a GSList of local candidates (NiceCandidate) belonging to @agent
 **/
NICEAPI_EXPORT GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id)
{
  Component *component;
  GSList * ret = NULL;
  GSList * item = NULL;

  g_static_rec_mutex_lock (&agent->mutex);
  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    {
      goto done;
    }

  for (item = component->local_candidates; item; item = item->next)
    ret = g_slist_append (ret, nice_candidate_copy (item->data));

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}


/**
 * nice_agent_get_remote_candidates:
 *  @agent: A NiceAgent
 *
 * The caller owns the returned GSList but not the candidates contained within
 * it.
 *
 * Note: the list of remote candidates can change during processing.
 * The client should register for the "new-remote-candidate" signal to
 * get notification of new remote candidates.
 *
 * Returns: a GSList of remote candidates (NiceCandidate) belonging to @agent
 **/
NICEAPI_EXPORT GSList *
nice_agent_get_remote_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id)
{
  Component *component;
  GSList *ret = NULL, *item = NULL;

  g_static_rec_mutex_lock (&agent->mutex);
  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    {
      goto done;
    }

  for (item = component->remote_candidates; item; item = item->next)
    ret = g_slist_append (ret, nice_candidate_copy (item->data));

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

/**
 * nice_agent_restart
 *  @agent: A NiceAgent
 *
 * Restarts the session as defined in ICE spec (ID-19). This function
 * needs to be called both when initiating (ICE spec section 9.1.1.1.
 * "ICE Restarts"), as well as when reacting (spec section 9.2.1.1. 
 * "Detecting ICE Restart") to a restart.
 *
 * Returns: FALSE on error
 **/
gboolean 
nice_agent_restart (
  NiceAgent *agent)
{
  GSList *i;
  gboolean res = TRUE;

  g_static_rec_mutex_lock (&agent->mutex);

  /* step: clean up all connectivity checks */
  conn_check_free (agent);

  /* step: regenerate tie-breaker value */
  priv_generate_tie_breaker (agent);

  for (i = agent->streams; i && res; i = i->next) {
    Stream *stream = i->data;

    /* step: reset local credentials for the stream and 
     * clean up the list of remote candidates */
    res = stream_restart (stream, agent->rng);
  }

  g_static_rec_mutex_unlock (&agent->mutex);
  return res;
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

  priv_remove_keepalive_timer (agent);

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

  nice_udp_socket_factory_close (&agent->udp_socket_factory);

  nice_udp_socket_factory_close (&agent->relay_socket_factory);


  g_static_rec_mutex_free (&agent->mutex);
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
  gchar buf[MAX_BUFFER_SIZE];
  guint len;

  g_static_rec_mutex_lock (&agent->mutex);

  /* note: dear compiler, these are for you: */
  (void)source;

  len = _nice_agent_recv (agent, stream, component, ctx->socket,
			  MAX_BUFFER_SIZE, buf);

  if (len > 0 && component->g_source_io_cb)
    component->g_source_io_cb (agent, stream->id, component->id,
        len, buf, component->data);

  g_static_rec_mutex_unlock (&agent->mutex);
  return TRUE;
}

/*
 * Attaches one socket handle to the main loop event context
 */

void
priv_attach_stream_component_socket (NiceAgent *agent,
    Stream *stream,
    Component *component,
    NiceUDPSocket *udp_socket)
{
  GIOChannel *io;
  GSource *source;
  IOCtx *ctx;

  if (!component->ctx)
    return;

  io = g_io_channel_unix_new (udp_socket->fileno);
  /* note: without G_IO_ERR the glib mainloop goes into
   *       busyloop if errors are encountered */
  source = g_io_create_watch (io, G_IO_IN | G_IO_ERR);
  ctx = io_ctx_new (agent, stream, component, udp_socket);
  g_source_set_callback (source, (GSourceFunc) nice_agent_g_source_cb,
      ctx, (GDestroyNotify) io_ctx_free);
  nice_debug ("Agent %p : Attach source %p (stream %u).", agent, source, stream->id);
  g_source_attach (source, component->ctx);
  component->gsources = g_slist_append (component->gsources, source);
}


/**
 * Attaches socket handles of 'stream' to the main eventloop
 * context.
 *
 */
static gboolean
priv_attach_stream_component (NiceAgent *agent,
    Stream *stream,
    Component *component)
{
  GSList *i;

  for (i = component->sockets; i; i = i->next)
    priv_attach_stream_component_socket (agent, stream, component, i->data);

  return TRUE;
}

/**
 * Detaches socket handles of 'stream' from the main eventloop
 * context.
 *
 */
static void priv_detach_stream_component (Stream *stream, Component *component)
{
  GSList *i;

  for (i = component->gsources; i; i = i->next) {
    GSource *source = i->data;
    nice_debug ("Detach source %p (stream %u).", source, stream->id);
    g_source_destroy (source);
  }

  g_slist_free (component->gsources);
  component->gsources = NULL;
}

NICEAPI_EXPORT gboolean
nice_agent_attach_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  GMainContext *ctx,
  NiceAgentRecvFunc func,
  gpointer data)
{
  Component *component = NULL;
  Stream *stream = NULL;
  gboolean ret = FALSE;

  g_static_rec_mutex_lock (&agent->mutex);

  /* attach candidates */

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    g_warning ("Could not find component %u in stream %u", component_id,
        stream_id);
    goto done;
  }

  if (component->g_source_io_cb && func == NULL)
    priv_detach_stream_component (stream, component);

  ret = TRUE;

  if (func && ctx) {
    component->g_source_io_cb = func;
    component->data = data;
    component->ctx = ctx;
    priv_attach_stream_component (agent, stream, component);
  } else {
    component->g_source_io_cb = NULL;
    component->data = NULL;
    component->ctx = NULL;
  }


 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

/**
 * Sets the selected candidate pair for media transmission
 * for given stream component. Calling this function will
 * disable all further ICE processing (connection check,
 * state machine updates, etc). Note that keepalives will
 * continue to be sent.
 */
NICEAPI_EXPORT gboolean
nice_agent_set_selected_pair (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const gchar *lfoundation,
  const gchar *rfoundation)
{
  Component *component;
  Stream *stream;
  CandidatePair pair;
  gboolean ret = FALSE;

  g_static_rec_mutex_lock (&agent->mutex);

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  if (!component_find_pair (component, agent, lfoundation, rfoundation, &pair)){
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream); 

  /* step: change component state */
  agent_signal_component_state_change (agent, stream_id, component_id, NICE_COMPONENT_STATE_READY);

  /* step: set the selected pair */
  component_update_selected_pair (component, &pair);
  agent_signal_new_selected_pair (agent, stream_id, component_id, lfoundation, rfoundation);

  ret = TRUE;

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}


guint agent_timeout_add_with_context (NiceAgent *agent, guint interval,
    GSourceFunc function, gpointer data)
{
  GSource *source;
  guint id;

  g_return_val_if_fail (function != NULL, 0);

  source = g_timeout_source_new (interval);

  g_source_set_callback (source, function, data, NULL);
  id = g_source_attach (source, agent->main_context);
  g_source_unref (source);

  return id;
}


/**
 * nice_agent_set_selected_remote_candidate:
 * @agent: a #NiceAgent
 * @stream_id: the stream id
 * @component_id: the component id
 * @candidate: the #NiceCandidate to force
 *
 * Sets the selected remote candidate for media transmission
 * for given stream component. Calling this function will
 * disable all further ICE processing (connection check,
 * state machine updates, etc). Note that keepalives will
 * continue to be sent.
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
NICEAPI_EXPORT gboolean
nice_agent_set_selected_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidate *candidate)
{
  Component *component;
  Stream *stream;
  NiceCandidate *lcandidate = NULL;
  gboolean ret = FALSE;

  g_static_rec_mutex_lock (&agent->mutex);

  /* step: check if the component exists*/
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream);


  /* step: set the selected pair */
  lcandidate = component_set_selected_remote_candidate (agent, component,
      candidate);
  if (!lcandidate)
    goto done;

  /* step: change component state */
  agent_signal_component_state_change (agent, stream_id, component_id, NICE_COMPONENT_STATE_READY);

  agent_signal_new_selected_pair (agent, stream_id, component_id,
      lcandidate->foundation,
      candidate->foundation);

  ret = TRUE;

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}
