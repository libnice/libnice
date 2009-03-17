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


#ifdef HAVE_CONFIG_H
# include <config.h>
#else
#define NICEAPI_EXPORT
#endif

#include <glib.h>

#include <string.h>
#include <errno.h>

#ifdef G_OS_WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "debug.h"

#include "socket.h"
#include "stun/usages/turn.h"
#include "candidate.h"
#include "component.h"
#include "conncheck.h"
#include "discovery.h"
#include "agent.h"
#include "agent-priv.h"
#include "agent-signals-marshal.h"

#include "stream.h"
#include "interfaces.h"

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
  PROP_MAX_CONNECTIVITY_CHECKS,
  PROP_PROXY_TYPE,
  PROP_PROXY_IP,
  PROP_PROXY_PORT,
  PROP_PROXY_USERNAME,
  PROP_PROXY_PASSWORD
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

StunUsageIceCompatibility
agent_to_ice_compatibility (NiceAgent *agent)
{
  return agent->compatibility == NICE_COMPATIBILITY_GOOGLE ?
      STUN_USAGE_ICE_COMPATIBILITY_GOOGLE :
      agent->compatibility == NICE_COMPATIBILITY_MSN ?
      STUN_USAGE_ICE_COMPATIBILITY_MSN :
      STUN_USAGE_ICE_COMPATIBILITY_DRAFT19;
}


StunUsageTurnCompatibility
agent_to_turn_compatibility (NiceAgent *agent)
{
  return agent->compatibility == NICE_COMPATIBILITY_GOOGLE ?
      STUN_USAGE_TURN_COMPATIBILITY_GOOGLE :
      agent->compatibility == NICE_COMPATIBILITY_MSN ?
      STUN_USAGE_TURN_COMPATIBILITY_MSN :
      agent->compatibility == NICE_COMPATIBILITY_WLM2009 ?
      STUN_USAGE_TURN_COMPATIBILITY_MSN : STUN_USAGE_TURN_COMPATIBILITY_DRAFT9;
}

NiceTurnSocketCompatibility
agent_to_turn_socket_compatibility (NiceAgent *agent)
{
  return agent->compatibility == NICE_COMPATIBILITY_GOOGLE ?
      NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE :
      agent->compatibility == NICE_COMPATIBILITY_MSN ?
      NICE_TURN_SOCKET_COMPATIBILITY_MSN :
      agent->compatibility == NICE_COMPATIBILITY_WLM2009 ?
      NICE_TURN_SOCKET_COMPATIBILITY_MSN :
      NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9;
}

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
  /**
   * NiceAgent:main-context:
   *
   * A GLib main context is needed for all timeouts used by libnice.
   * This is a property being set by the nice_agent_new() call.
   */
  g_object_class_install_property (gobject_class, PROP_MAIN_CONTEXT,
      g_param_spec_pointer (
         "main-context",
         "The GMainContext to use for timeouts",
         "The GMainContext to use for timeouts",
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  /**
   * NiceAgent:compatibility:
   *
   * The Nice agent can work in various compatibility modes depending on
   * what the application/peer needs.
   * <para> See also: #NiceCompatibility</para>
   */
  g_object_class_install_property (gobject_class, PROP_COMPATIBILITY,
      g_param_spec_uint (
         "compatibility",
         "ICE specification compatibility",
         "The compatibility mode for the agent",
         NICE_COMPATIBILITY_DRAFT19, NICE_COMPATIBILITY_LAST,
         NICE_COMPATIBILITY_DRAFT19,
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

  g_object_class_install_property (gobject_class, PROP_PROXY_IP,
      g_param_spec_string (
        "proxy-ip",
        "Proxy server IP",
        "The proxy server used to bypass a proxy firewall",
        NULL,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_PROXY_PORT,
      g_param_spec_uint (
        "proxy-port",
        "Proxy server port",
        "The Proxy server used to bypass a proxy firewall",
        1, 65536,
	1,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_PROXY_TYPE,
      g_param_spec_uint (
         "proxy-type",
         "Type of proxy to use",
         "The type of proxy set in the proxy-ip property",
         NICE_PROXY_TYPE_NONE, NICE_PROXY_TYPE_LAST,
         NICE_PROXY_TYPE_NONE,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_PROXY_USERNAME,
      g_param_spec_string (
        "proxy-username",
        "Proxy server username",
        "The username used to authenticate with the proxy",
        NULL,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_PROXY_PASSWORD,
      g_param_spec_string (
        "proxy-password",
        "Proxy server password",
        "The password used to authenticate with the proxy",
        NULL,
        G_PARAM_READWRITE));

  /* install signals */

  /**
   * NiceAgent::component-state-changed
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @state: The #NiceComponentState of the component
   *
   * This signal is fired whenever a component's state changes
   */
  signals[SIGNAL_COMPONENT_STATE_CHANGED] =
      g_signal_new (
          "component-state-changed",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT_UINT,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT,
          G_TYPE_INVALID);

  /**
   * NiceAgent::candidate-gathering-done:
   * @stream_id: The ID of the stream
   *
   * This signal is fired whenever a stream has finished gathering its
   * candidates after a call to nice_agent_gather_candidates()
   */
  signals[SIGNAL_CANDIDATE_GATHERING_DONE] =
      g_signal_new (
          "candidate-gathering-done",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT,
          G_TYPE_NONE,
          1,
          G_TYPE_UINT, G_TYPE_INVALID);

  /**
   * NiceAgent::new-selected-pair
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @lfoundation: The local foundation of the selected candidate pair
   * @rfoundation: The remote foundation of the selected candidate pair
   *
   * This signal is fired once a candidate pair is selected for data transfer for
   * a stream's component
   */
  signals[SIGNAL_NEW_SELECTED_PAIR] =
      g_signal_new (
          "new-selected-pair",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT_STRING_STRING,
          G_TYPE_NONE,
          4,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING,
          G_TYPE_INVALID);

  /**
   * NiceAgent::new-candidate
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @foundation: The foundation of the new candidate
   *
   * This signal is fired when the agent discovers a new candidate
   * <para> See also: #NiceAgent::candidates-gathering-done </para>
   */
  signals[SIGNAL_NEW_CANDIDATE] =
      g_signal_new (
          "new-candidate",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT_STRING,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING,
          G_TYPE_INVALID);

  /**
   * NiceAgent::new-remote-candidate
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @foundation: The foundation of the new candidate
   *
   * This signal is fired when the agent discovers a new remote candidate.
   * This can happen with peer reflexive candidates.
   * <para> See also: #NiceAgent::candidates-gathering-done </para>
   */
  signals[SIGNAL_NEW_REMOTE_CANDIDATE] =
      g_signal_new (
          "new-remote-candidate",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT_STRING,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING,
          G_TYPE_INVALID);

  /**
   * NiceAgent::initial-binding-request-received
   * @stream_id: The ID of the stream
   *
   * This signal is fired when we received our first binding request from
   * the peer.
   */
  signals[SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED] =
      g_signal_new (
          "initial-binding-request-received",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT,
          G_TYPE_NONE,
          1,
          G_TYPE_UINT,
          G_TYPE_INVALID);

  /* Init debug options depending on env variables */
  nice_debug_init ();
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
  agent->discovery_timer_source = NULL;
  agent->conncheck_timer_source = NULL;
  agent->keepalive_timer_source = NULL;
  agent->refresh_list = NULL;

  agent->compatibility = NICE_COMPATIBILITY_DRAFT19;

  stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
      STUN_AGENT_USAGE_USE_FINGERPRINT);

  agent->rng = nice_rng_new ();
  priv_generate_tie_breaker (agent);

  g_static_rec_mutex_init (&agent->mutex);
}


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

    case PROP_PROXY_IP:
      g_value_set_string (value, agent->proxy_ip);
      break;

    case PROP_PROXY_PORT:
      g_value_set_uint (value, agent->proxy_port);
      break;

    case PROP_PROXY_TYPE:
      g_value_set_uint (value, agent->proxy_type);
      break;

    case PROP_PROXY_USERNAME:
      g_value_set_string (value, agent->proxy_username);
      break;

    case PROP_PROXY_PASSWORD:
      g_value_set_string (value, agent->proxy_password);
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
      if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
      } else if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_FORCE_VALIDATER);
      } else if (agent->compatibility == NICE_COMPATIBILITY_WLM2009) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_WLM2009,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_USE_FINGERPRINT);
      } else {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC5389,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_USE_FINGERPRINT);
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

    case PROP_PROXY_IP:
      agent->proxy_ip = g_value_dup_string (value);
      break;

    case PROP_PROXY_PORT:
      agent->proxy_port = g_value_get_uint (value);
      break;

    case PROP_PROXY_TYPE:
      agent->proxy_type = g_value_get_uint (value);
      break;

    case PROP_PROXY_USERNAME:
      agent->proxy_username = g_value_dup_string (value);
      break;

    case PROP_PROXY_PASSWORD:
      agent->proxy_password = g_value_dup_string (value);
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
	{
	  gchar tmpbuf[INET6_ADDRSTRLEN];
	  nice_address_to_string (&local_candidate->addr, tmpbuf);
          nice_debug ("Agent %p: gathered local candidate : [%s]:%u"
              " for s%d/c%d. U/P '%s'/'%s'", agent,
              tmpbuf, nice_address_get_port (&local_candidate->addr),
              local_candidate->stream_id, local_candidate->component_id,
              local_candidate->username, local_candidate->password);
	}
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
  GSList *i;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    if (stream->gathering) {
      stream->gathering = FALSE;
      g_signal_emit (agent, signals[SIGNAL_CANDIDATE_GATHERING_DONE], 0, stream->id);
    }
  }
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

  if (component->selected_pair.local->type == NICE_CANDIDATE_TYPE_RELAYED) {
    nice_turn_socket_set_peer (component->selected_pair.local->sockptr,
                                   &component->selected_pair.remote->addr);
  }

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
priv_add_new_candidate_discovery_stun (NiceAgent *agent,
    NiceSocket *socket, NiceAddress server,
    Stream *stream, guint component_id)
{
  CandidateDiscovery *cdisco;
  GSList *modified_list;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);
  if (cdisco) {
    modified_list = g_slist_append (agent->discovery_list, cdisco);

    if (modified_list) {
      cdisco->type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
      cdisco->nicesock = socket;
      cdisco->server = server;
      cdisco->stream = stream;
      cdisco->component = stream_find_component_by_id (stream, component_id);
      cdisco->agent = agent;
      stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
          STUN_COMPATIBILITY_RFC3489, 0);

      nice_debug ("Agent %p : Adding new srv-rflx candidate discovery %p\n", agent, cdisco);
      agent->discovery_list = modified_list;
      ++agent->discovery_unsched_items;
    }

    return TRUE;
  }

  return FALSE;
}

static gboolean
priv_add_new_candidate_discovery_turn (NiceAgent *agent,
    NiceSocket *socket, TurnServer *turn,
    Stream *stream, guint component_id)
{
  CandidateDiscovery *cdisco;
  GSList *modified_list;
  GSList *socket_modified_list;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);
  if (cdisco) {
    modified_list = g_slist_append (agent->discovery_list, cdisco);

    if (modified_list) {
      Component *component = stream_find_component_by_id (stream, component_id);

      cdisco->type = NICE_CANDIDATE_TYPE_RELAYED;

      if (turn->type ==  NICE_RELAY_TYPE_TURN_UDP) {
        if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
          NiceAddress addr = socket->addr;
          NiceSocket *new_socket;
          nice_address_set_port (&addr, 0);

          new_socket = nice_udp_bsd_socket_new (&addr);
          if (new_socket) {
            agent_attach_stream_component_socket (agent, stream,
                component, new_socket);
            socket_modified_list = g_slist_append (component->sockets, new_socket);
            if (socket_modified_list) {
              /* success: store a pointer to the sockaddr */
              component->sockets = socket_modified_list;
              socket = new_socket;
            } else {
              nice_socket_free (new_socket);
            }
          }
        }
        cdisco->nicesock = socket;
      } else {
        NiceAddress proxy_server;
        socket = NULL;

        if (agent->proxy_type != NICE_PROXY_TYPE_NONE &&
            agent->proxy_ip != NULL &&
            nice_address_set_from_string (&proxy_server, agent->proxy_ip)) {
          nice_address_set_port (&proxy_server, agent->proxy_port);
          socket = nice_tcp_bsd_socket_new (agent, component->ctx, &proxy_server);

          if (socket) {
            if (agent->proxy_type == NICE_PROXY_TYPE_SOCKS5) {
              socket = nice_socks5_socket_new (socket, &turn->server,
                  agent->proxy_username, agent->proxy_password);
            } else if (agent->proxy_type == NICE_PROXY_TYPE_HTTP){
              socket = nice_http_socket_new (socket, &turn->server,
                  agent->proxy_username, agent->proxy_password);
            } else {
              /* TODO add HTTP support */
              nice_socket_free (socket);
              socket = NULL;
            }
          }

        }
        if (socket == NULL) {
          socket = nice_tcp_bsd_socket_new (agent, component->ctx, &turn->server);
        }
        if (turn->type ==  NICE_RELAY_TYPE_TURN_TLS &&
            agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
          socket = nice_pseudossl_socket_new (agent, socket);
        }
        cdisco->nicesock = nice_tcp_turn_socket_new (agent, socket,
            agent_to_turn_socket_compatibility (agent));

        if (!cdisco->nicesock) {
          agent->discovery_list = g_slist_remove (modified_list, cdisco);
          g_slice_free (CandidateDiscovery, cdisco);
          return FALSE;
        }

        agent_attach_stream_component_socket (agent, stream,
            component, cdisco->nicesock);
        socket_modified_list = g_slist_append (component->sockets, cdisco->nicesock);
        if (socket_modified_list) {
          /* success: store a pointer to the sockaddr */
          component->sockets = socket_modified_list;
        }
      }
      cdisco->turn = turn;
      cdisco->server = turn->server;

      cdisco->stream = stream;
      cdisco->component = stream_find_component_by_id (stream, component_id);
      cdisco->agent = agent;

      if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
        stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
      } else if (agent->compatibility == NICE_COMPATIBILITY_MSN ||
                 agent->compatibility == NICE_COMPATIBILITY_WLM2009) {
        stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS);
      } else {
        stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC5389,
            STUN_AGENT_USAGE_ADD_SOFTWARE |
            STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS);
      }

      nice_debug ("Agent %p : Adding new relay-rflx candidate discovery %p\n",
          agent, cdisco);
      agent->discovery_list = modified_list;
      ++agent->discovery_unsched_items;
    }

    return TRUE;
  }

  return FALSE;
}

NICEAPI_EXPORT guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components)
{
  Stream *stream;
  GSList *modified_list = NULL;
  guint ret = 0;

  g_static_rec_mutex_lock (&agent->mutex);

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

  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}


NICEAPI_EXPORT gboolean
nice_agent_set_relay_info(NiceAgent *agent,
    guint stream_id, guint component_id,
    const gchar *server_ip, guint server_port,
    const gchar *username, const gchar *password,
    NiceRelayType type)
{

  Component *component = NULL;

  g_return_val_if_fail (server_ip, FALSE);
  g_return_val_if_fail (server_port, FALSE);
  g_return_val_if_fail (username, FALSE);
  g_return_val_if_fail (password, FALSE);
  g_return_val_if_fail (type <= NICE_PROXY_TYPE_LAST, FALSE);

  g_static_rec_mutex_lock (&agent->mutex);

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    TurnServer *turn = g_slice_new0 (TurnServer);
    nice_address_init (&turn->server);

    if (nice_address_set_from_string (&turn->server, server_ip)) {
      nice_address_set_port (&turn->server, server_port);
    } else {
      g_slice_free (TurnServer, turn);
      g_static_rec_mutex_unlock (&agent->mutex);
      return FALSE;
    }


    turn->username = g_strdup (username);
    turn->password = g_strdup (password);
    turn->type = type;

    nice_debug ("Agent %p: added relay server [%s]:%d of type %d", agent,
        server_ip, server_port, type);

    component->turn_servers = g_list_append (component->turn_servers, turn);
  }

  g_static_rec_mutex_unlock (&agent->mutex);
  return TRUE;
}


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

  nice_debug ("Agent %p : In %s mode, starting candidate gathering.", agent,
      agent->full_mode ? "ICE-FULL" : "ICE-LITE");

  /* if no local addresses added, generate them ourselves */
  if (agent->local_addresses == NULL) {
    GList *addresses = nice_interfaces_get_local_ips (FALSE);
    GList *item;

    for (item = addresses; item; item = g_list_next (item)) {
      NiceAddress *addr = nice_address_new ();

      if (nice_address_set_from_string (addr, item->data)) {
        nice_agent_add_local_address (agent, addr);
      }
      nice_address_free (addr);
    }

    g_list_foreach (addresses, (GFunc) g_free, NULL);
    g_list_free (addresses);
  }

  /* generate a local host candidate for each local address */
  for (i = agent->local_addresses; i; i = i->next){
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
        if (nice_address_set_from_string (&stun_server, agent->stun_server_ip)) {
		  gboolean res;
          nice_address_set_port (&stun_server, agent->stun_server_port);

          res =
              priv_add_new_candidate_discovery_stun (agent,
                  host_candidate->sockptr,
                  stun_server,
                  stream,
                  n + 1);

          if (res != TRUE) {
            /* note: memory allocation failure, return error */
            g_error ("Memory allocation failure?");
          }
        }
      }

      if (agent->full_mode && component) {
        GList *item;

        for (item = component->turn_servers; item; item = item->next) {
          TurnServer *turn = item->data;

          gboolean res =
              priv_add_new_candidate_discovery_turn (agent,
                  host_candidate->sockptr,
                  turn,
                  stream,
                  n + 1);

          if (res != TRUE) {
            /* note: memory allocation failure, return error */
            g_error ("Memory allocation failure?");
          }
        }
      }
    }
  }

  stream->gathering = TRUE;


  /* note: no async discoveries pending, signal that we are ready */
  if (agent->discovery_unsched_items == 0) {
    nice_debug ("Agent %p: Candidate gathering FINISHED, no scheduled items.",
        agent);
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
  if (agent->keepalive_timer_source != NULL) {
    g_source_destroy (agent->keepalive_timer_source);
    g_source_unref (agent->keepalive_timer_source);
    agent->keepalive_timer_source = NULL;
  }
}

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
  refresh_prune_stream (agent, stream_id);

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
	{
	  gchar tmpbuf[INET6_ADDRSTRLEN];
	  nice_address_to_string (addr, tmpbuf);
	  nice_debug ("Agent %p : Adding remote candidate with addr [%s]:%u"
              " for s%d/c%d. U/P '%s'/'%s'", agent, tmpbuf,
              nice_address_get_port (addr), stream_id, component_id,
              username, password);
	}
	
	if (base_addr)
	  candidate->base_addr = *base_addr;
	
	candidate->transport = transport;
	candidate->priority = priority;
	candidate->username = g_strdup (username);
	candidate->password = g_strdup (password);
	
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
    return FALSE;
  }

  return TRUE;
}

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


NICEAPI_EXPORT gboolean
nice_agent_get_local_credentials (
  NiceAgent *agent,
  guint stream_id,
  gchar **ufrag, gchar **pwd)
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

  *ufrag = g_strdup (stream->local_ufrag);
  *pwd = g_strdup (stream->local_password);
  ret = TRUE;

 done:

  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

NICEAPI_EXPORT int
nice_agent_set_remote_candidates (NiceAgent *agent, guint stream_id, guint component_id, const GSList *candidates)
{
  const GSList *i; 
  int added = 0;
  Stream *stream;

  nice_debug ("Agent %p: set_remote_candidates %d %d", agent, stream_id, component_id);

  g_static_rec_mutex_lock (&agent->mutex);

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    added = -1;
    goto done;
  }

  if (agent->discovery_unsched_items > 0 || stream->gathering) {
    nice_debug ("Agent %p: Remote candidates refused for stream %d because "
        "we are still gathering our own candidates", agent, stream_id);
    added = -1;
    goto done;
  }

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

 done:
 g_static_rec_mutex_unlock (&agent->mutex);
 return added;
}


static gint
_nice_agent_recv (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceSocket *socket,
  guint buf_len,
  gchar *buf)
{
  NiceAddress from;
  gint len;
  GList *item;

  len = nice_socket_recv (socket, &from,  buf_len, buf);

  if (len <= 0)
    return len;

#ifndef NDEBUG
  if (len > 0) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (&from, tmpbuf);
    nice_debug ("Agent %p : Packet received on local socket %u from [%s]:%u (%u octets).", agent,
        socket->fileno, tmpbuf, nice_address_get_port (&from), len);
  }
#endif


  if ((guint)len > buf_len)
    {
      /* buffer is not big enough to accept this packet */
      /* XXX: test this case */
      return 0;
    }

  for (item = component->turn_servers; item; item = g_list_next (item)) {
    TurnServer *turn = item->data;
    if (nice_address_equal (&from, &turn->server)) {
      GSList * i = NULL;
#ifndef NDEBUG
      nice_debug ("Agent %p : Packet received from TURN server candidate.",
          agent);
#endif
      for (i = component->local_candidates; i; i = i->next) {
        NiceCandidate *cand = i->data;
        if (cand->type == NICE_CANDIDATE_TYPE_RELAYED &&
            cand->stream_id == stream->id &&
            cand->component_id == component->id) {
          len = nice_turn_socket_parse_recv (cand->sockptr, &socket,
              &from, len, buf, &from, buf, len);
        }
      }
      break;
    }
  }

  if (stun_message_validate_buffer_length ((uint8_t *) buf, (size_t) len) != len)
    /* If the retval is no 0, its not a valid stun packet, probably data */
    return len;


  if (conn_check_handle_inbound_stun (agent, stream, component, socket,
          &from, buf, len))
    /* handled STUN message*/
    return 0;

  /* unhandled STUN, pass to client */
  return len;
}


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
      NiceSocket *sock;
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
      if (nice_socket_send (sock, addr, len, buf)) {
        ret = len;
      }
      goto done;
    }

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}


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
  refresh_free (agent);
  g_assert (agent->refresh_list == NULL);

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

  g_static_rec_mutex_free (&agent->mutex);
}


typedef struct _IOCtx IOCtx;

struct _IOCtx
{
  GIOChannel *channel;
  GSource *source;
  NiceAgent *agent;
  Stream *stream;
  Component *component;
  NiceSocket *socket;
};


static IOCtx *
io_ctx_new (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceSocket *socket,
  GIOChannel *channel,
  GSource *source)
{
  IOCtx *ctx;

  ctx = g_slice_new0 (IOCtx);
  if (ctx) {
    ctx->agent = agent;
    ctx->stream = stream;
    ctx->component = component;
    ctx->socket = socket;
    ctx->channel = channel;
    ctx->source = source;
  }
  return ctx;
}


static void
io_ctx_free (IOCtx *ctx)
{
  g_io_channel_unref (ctx->channel);
  g_slice_free (IOCtx, ctx);
}

static gboolean
nice_agent_g_source_cb (
  GIOChannel *io,
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
  gint len;

  g_static_rec_mutex_lock (&agent->mutex);

  /* note: dear compiler, these are for you: */
  (void)io;

  len = _nice_agent_recv (agent, stream, component, ctx->socket,
			  MAX_BUFFER_SIZE, buf);

  if (len > 0 && component->g_source_io_cb) {
    component->g_source_io_cb (agent, stream->id, component->id,
        len, buf, component->data);
  } else if (len < 0) {
    GSource *source = ctx->source;
    component->gsources = g_slist_remove (component->gsources, source);
    g_source_destroy (source);
    g_source_unref (source);
    /* We don't close the socket because it would be way too complicated to
     * take care of every path where the socket might still be used.. */
    nice_debug ("Agent %p: unable to recv from socket %p. Detaching", agent,
        ctx->socket);
  }

  g_static_rec_mutex_unlock (&agent->mutex);
  return TRUE;
}

/*
 * Attaches one socket handle to the main loop event context
 */

void
agent_attach_stream_component_socket (NiceAgent *agent,
    Stream *stream,
    Component *component,
    NiceSocket *socket)
{
  GIOChannel *io;
  GSource *source;
  IOCtx *ctx;

  if (!component->ctx)
    return;

  io = g_io_channel_unix_new (socket->fileno);
  /* note: without G_IO_ERR the glib mainloop goes into
   *       busyloop if errors are encountered */
  source = g_io_create_watch (io, G_IO_IN | G_IO_ERR);
  ctx = io_ctx_new (agent, stream, component, socket, io, source);
  g_source_set_callback (source, (GSourceFunc) nice_agent_g_source_cb,
      ctx, (GDestroyNotify) io_ctx_free);
  nice_debug ("Agent %p : Attach source %p (stream %u).", agent, source, stream->id);
  g_source_attach (source, component->ctx);
  component->gsources = g_slist_append (component->gsources, source);
}


/*
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
    agent_attach_stream_component_socket (agent, stream, component, i->data);

  return TRUE;
}

/*
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
    g_source_unref (source);
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


GSource* agent_timeout_add_with_context (NiceAgent *agent, guint interval,
    GSourceFunc function, gpointer data)
{
  GSource *source;
  guint id;

  g_return_val_if_fail (function != NULL, 0);

  source = g_timeout_source_new (interval);

  g_source_set_callback (source, function, data, NULL);
  id = g_source_attach (source, agent->main_context);

  return source;
}


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
