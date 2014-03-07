/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2010, 2013 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2010 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
 *   Kai Vehmanen, Nokia
 *   Philip Withnall, Collabora Ltd.
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
#include <gobject/gvaluecollector.h>

#include <string.h>
#include <errno.h>

#ifndef G_OS_WIN32
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
#include "iostream.h"

#include "stream.h"
#include "interfaces.h"

#include "pseudotcp.h"

/* Maximum size of a UDP packet’s payload, as the packet’s length field is 16b
 * wide. */
#define MAX_BUFFER_SIZE ((1 << 16) - 1)  /* 65535 */

#define DEFAULT_STUN_PORT  3478
#define DEFAULT_UPNP_TIMEOUT 200

#define MAX_TCP_MTU 1400 /* Use 1400 because of VPNs and we assume IEE 802.3 */

static void
nice_debug_input_message_composition (const NiceInputMessage *messages,
    guint n_messages);

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
  PROP_PROXY_PASSWORD,
  PROP_UPNP,
  PROP_UPNP_TIMEOUT,
  PROP_RELIABLE
};


enum
{
  SIGNAL_COMPONENT_STATE_CHANGED,
  SIGNAL_CANDIDATE_GATHERING_DONE,
  SIGNAL_NEW_SELECTED_PAIR,
  SIGNAL_NEW_CANDIDATE,
  SIGNAL_NEW_REMOTE_CANDIDATE,
  SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED,
  SIGNAL_RELIABLE_TRANSPORT_WRITABLE,
  SIGNAL_STREAMS_REMOVED,
  N_SIGNALS,
};

static guint signals[N_SIGNALS];

#if GLIB_CHECK_VERSION(2,31,8)
static GMutex agent_mutex;    /* Mutex used for thread-safe lib */
#else
static GStaticMutex agent_mutex = G_STATIC_REC_MUTEX_INIT;
#endif

static void priv_free_upnp (NiceAgent *agent);

#if GLIB_CHECK_VERSION(2,31,8)
void agent_lock (void)
{
  g_mutex_lock (&agent_mutex);
}

void agent_unlock (void)
{
  g_mutex_unlock (&agent_mutex);
}

#else
void agent_lock(void)
{
  g_static_mutex_lock (&agent_mutex);
}

void agent_unlock(void)
{
  g_static_mutex_unlock (&agent_mutex);
}

#endif

typedef struct {
  guint signal_id;
  GSignalQuery query;
  GValue *params;
} QueuedSignal;


static void
free_queued_signal (QueuedSignal *sig)
{
  guint i;

  for (i = 0; i < sig->query.n_params; i++) {
    if (G_VALUE_HOLDS_POINTER (&sig->params[i]))
      g_free (g_value_get_pointer (&sig->params[i]));
    g_value_unset (&sig->params[i]);
  }

  g_slice_free1 (sizeof(GValue) * (sig->query.n_params + 1), sig->params);
  g_slice_free (QueuedSignal, sig);
}

void
agent_unlock_and_emit (NiceAgent *agent)
{
  GQueue queue = G_QUEUE_INIT;
  QueuedSignal *sig;

  queue = agent->pending_signals;
  g_queue_init (&agent->pending_signals);

  agent_unlock ();

  while ((sig = g_queue_pop_head (&queue))) {
    g_signal_emitv (sig->params, sig->signal_id, 0, NULL);

    free_queued_signal (sig);
  }
}

static void
agent_queue_signal (NiceAgent *agent, guint signal_id, ...)
{
  QueuedSignal *sig;
  guint i;
  gchar *error = NULL;
  va_list var_args;

  sig = g_slice_new (QueuedSignal);
  g_signal_query (signal_id, &sig->query);

  sig->signal_id = signal_id;
  sig->params = g_slice_alloc0 (sizeof(GValue) * (sig->query.n_params + 1));

  g_value_init (&sig->params[0], G_TYPE_OBJECT);
  g_value_set_object (&sig->params[0], agent);

  va_start (var_args, signal_id);
  for (i = 0; i < sig->query.n_params; i++) {
    G_VALUE_COLLECT_INIT (&sig->params[i + 1], sig->query.param_types[i],
        var_args, 0, &error);
    if (error)
      break;
  }
  va_end (var_args);

  if (error) {
    free_queued_signal (sig);
    g_critical ("Error collecting values for signal: %s", error);
    g_free (error);
    return;
  }

  g_queue_push_tail (&agent->pending_signals, sig);
}


StunUsageIceCompatibility
agent_to_ice_compatibility (NiceAgent *agent)
{
  return agent->compatibility == NICE_COMPATIBILITY_GOOGLE ?
      STUN_USAGE_ICE_COMPATIBILITY_GOOGLE :
      agent->compatibility == NICE_COMPATIBILITY_MSN ?
      STUN_USAGE_ICE_COMPATIBILITY_MSN :
      agent->compatibility == NICE_COMPATIBILITY_WLM2009 ?
      STUN_USAGE_ICE_COMPATIBILITY_WLM2009 :
      agent->compatibility == NICE_COMPATIBILITY_OC2007 ?
      STUN_USAGE_ICE_COMPATIBILITY_MSN :
      agent->compatibility == NICE_COMPATIBILITY_OC2007R2 ?
      STUN_USAGE_ICE_COMPATIBILITY_WLM2009 :
      STUN_USAGE_ICE_COMPATIBILITY_RFC5245;
}


StunUsageTurnCompatibility
agent_to_turn_compatibility (NiceAgent *agent)
{
  return agent->compatibility == NICE_COMPATIBILITY_GOOGLE ?
      STUN_USAGE_TURN_COMPATIBILITY_GOOGLE :
      agent->compatibility == NICE_COMPATIBILITY_MSN ?
      STUN_USAGE_TURN_COMPATIBILITY_MSN :
      agent->compatibility == NICE_COMPATIBILITY_WLM2009 ?
      STUN_USAGE_TURN_COMPATIBILITY_MSN :
      agent->compatibility == NICE_COMPATIBILITY_OC2007 ?
      STUN_USAGE_TURN_COMPATIBILITY_OC2007 :
      agent->compatibility == NICE_COMPATIBILITY_OC2007R2 ?
      STUN_USAGE_TURN_COMPATIBILITY_OC2007 :
      STUN_USAGE_TURN_COMPATIBILITY_RFC5766;
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
      agent->compatibility == NICE_COMPATIBILITY_OC2007 ?
      NICE_TURN_SOCKET_COMPATIBILITY_OC2007 :
      agent->compatibility == NICE_COMPATIBILITY_OC2007R2 ?
      NICE_TURN_SOCKET_COMPATIBILITY_OC2007 :
      NICE_TURN_SOCKET_COMPATIBILITY_RFC5766;
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
         NICE_COMPATIBILITY_RFC5245, NICE_COMPATIBILITY_LAST,
         NICE_COMPATIBILITY_RFC5245,
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER,
      g_param_spec_string (
        "stun-server",
        "STUN server IP address",
        "The IP address (not the hostname) of the STUN server to use",
        NULL,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER_PORT,
      g_param_spec_uint (
        "stun-server-port",
        "STUN server port",
        "Port of the STUN server used to gather server-reflexive candidates",
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
        "Timer 'Ta' (msecs) used in the IETF ICE specification for pacing "
        "candidate gathering and sending of connectivity checks",
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

  /**
   * NiceAgent:proxy-ip:
   *
   * The proxy server IP used to bypass a proxy firewall
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_IP,
      g_param_spec_string (
        "proxy-ip",
        "Proxy server IP",
        "The proxy server IP used to bypass a proxy firewall",
        NULL,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-port:
   *
   * The proxy server port used to bypass a proxy firewall
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_PORT,
      g_param_spec_uint (
        "proxy-port",
        "Proxy server port",
        "The Proxy server port used to bypass a proxy firewall",
        1, 65536,
	1,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-type:
   *
   * The type of proxy set in the proxy-ip property
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_TYPE,
      g_param_spec_uint (
         "proxy-type",
         "Type of proxy to use",
         "The type of proxy set in the proxy-ip property",
         NICE_PROXY_TYPE_NONE, NICE_PROXY_TYPE_LAST,
         NICE_PROXY_TYPE_NONE,
         G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-username:
   *
   * The username used to authenticate with the proxy
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_USERNAME,
      g_param_spec_string (
        "proxy-username",
        "Proxy server username",
        "The username used to authenticate with the proxy",
        NULL,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-password:
   *
   * The password used to authenticate with the proxy
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_PASSWORD,
      g_param_spec_string (
        "proxy-password",
        "Proxy server password",
        "The password used to authenticate with the proxy",
        NULL,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:upnp:
   *
   * Whether the agent should use UPnP to open a port in the router and
   * get the external IP
   *
   * Since: 0.0.7
   */
   g_object_class_install_property (gobject_class, PROP_UPNP,
      g_param_spec_boolean (
        "upnp",
#ifdef HAVE_GUPNP
        "Use UPnP",
        "Whether the agent should use UPnP to open a port in the router and "
        "get the external IP",
#else
        "Use UPnP (disabled in build)",
        "Does nothing because libnice was not built with UPnP support",
#endif
	TRUE, /* enable UPnP by default */
        G_PARAM_READWRITE| G_PARAM_CONSTRUCT));

  /**
   * NiceAgent:upnp-timeout:
   *
   * The maximum amount of time to wait for UPnP discovery to finish before
   * signaling the #NiceAgent::candidate-gathering-done signal
   *
   * Since: 0.0.7
   */
  g_object_class_install_property (gobject_class, PROP_UPNP_TIMEOUT,
      g_param_spec_uint (
        "upnp-timeout",
#ifdef HAVE_GUPNP
        "Timeout for UPnP discovery",
        "The maximum amount of time to wait for UPnP discovery to finish before "
        "signaling the candidate-gathering-done signal",
#else
        "Timeout for UPnP discovery (disabled in build)",
        "Does nothing because libnice was not built with UPnP support",
#endif
        100, 60000,
	DEFAULT_UPNP_TIMEOUT,
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

  /**
   * NiceAgent:reliable:
   *
   * Whether the agent should use PseudoTcp to ensure a reliable transport
   * of messages
   *
   * Since: 0.0.11
   */
   g_object_class_install_property (gobject_class, PROP_RELIABLE,
      g_param_spec_boolean (
        "reliable",
        "reliable mode",
        "Whether the agent should use PseudoTcp to ensure a reliable transport"
        "of messages",
	FALSE,
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  /* install signals */

  /**
   * NiceAgent::component-state-changed
   * @agent: The #NiceAgent object
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
   * @agent: The #NiceAgent object
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
   * @agent: The #NiceAgent object
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
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @foundation: The foundation of the new candidate
   *
   * This signal is fired when the agent discovers a new candidate
   * <para> See also: #NiceAgent::candidate-gathering-done </para>
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
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @foundation: The foundation of the new candidate
   *
   * This signal is fired when the agent discovers a new remote candidate.
   * This can happen with peer reflexive candidates.
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
   * @agent: The #NiceAgent object
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

  /**
   * NiceAgent::reliable-transport-writable
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   *
   * This signal is fired on the reliable #NiceAgent when the underlying reliable
   * transport becomes writable.
   * This signal is only emitted when the nice_agent_send() function returns less
   * bytes than requested to send (or -1) and once when the connection
   * is established.
   *
   * Since: 0.0.11
   */
  signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE] =
      g_signal_new (
          "reliable-transport-writable",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          agent_marshal_VOID__UINT_UINT,
          G_TYPE_NONE,
          2,
          G_TYPE_UINT, G_TYPE_UINT,
          G_TYPE_INVALID);

  /**
   * NiceAgent::streams-removed
   * @agent: The #NiceAgent object
   * @stream_ids: (array zero-terminated=1) (element-type uint): An array of
   * unsigned integer stream IDs, ending with a 0 ID
   *
   * This signal is fired whenever one or more streams are removed from the
   * @agent.
   *
   * Since: 0.1.5
   */
  signals[SIGNAL_STREAMS_REMOVED] =
      g_signal_new (
          "streams-removed",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_VOID__POINTER,
          G_TYPE_NONE,
          1,
          G_TYPE_POINTER,
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
  agent->media_after_tick = FALSE;
  agent->software_attribute = NULL;

  agent->compatibility = NICE_COMPATIBILITY_RFC5245;
  agent->reliable = FALSE;

  stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
      STUN_AGENT_USAGE_USE_FINGERPRINT);

  agent->rng = nice_rng_new ();
  priv_generate_tie_breaker (agent);

  g_queue_init (&agent->pending_signals);
}


NICEAPI_EXPORT NiceAgent *
nice_agent_new (GMainContext *ctx, NiceCompatibility compat)
{
  NiceAgent *agent = g_object_new (NICE_TYPE_AGENT,
      "compatibility", compat,
      "main-context", ctx,
      "reliable", FALSE,
      NULL);

  return agent;
}


NICEAPI_EXPORT NiceAgent *
nice_agent_new_reliable (GMainContext *ctx, NiceCompatibility compat)
{
  NiceAgent *agent = g_object_new (NICE_TYPE_AGENT,
      "compatibility", compat,
      "main-context", ctx,
      "reliable", TRUE,
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

  agent_lock();

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

    case PROP_UPNP:
#ifdef HAVE_GUPNP
      g_value_set_boolean (value, agent->upnp_enabled);
#else
      g_value_set_boolean (value, FALSE);
#endif
      break;

    case PROP_UPNP_TIMEOUT:
#ifdef HAVE_GUPNP
      g_value_set_uint (value, agent->upnp_timeout);
#else
      g_value_set_uint (value, DEFAULT_UPNP_TIMEOUT);
#endif
      break;

    case PROP_RELIABLE:
      g_value_set_boolean (value, agent->reliable);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  agent_unlock_and_emit(agent);
}


static void
nice_agent_set_property (
  GObject *object,
  guint property_id,
  const GValue *value,
  GParamSpec *pspec)
{
  NiceAgent *agent = NICE_AGENT (object);

  agent_lock();

  switch (property_id)
    {
    case PROP_MAIN_CONTEXT:
      agent->main_context = g_value_get_pointer (value);
      if (agent->main_context != NULL)
        g_main_context_ref (agent->main_context);
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
      } else if (agent->compatibility == NICE_COMPATIBILITY_OC2007) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC3489,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_FORCE_VALIDATER |
            STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
      } else if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_WLM2009,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_USE_FINGERPRINT |
            STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
      } else {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC5389,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_USE_FINGERPRINT);
      }
      stun_agent_set_software (&agent->stun_agent, agent->software_attribute);

      break;

    case PROP_STUN_SERVER:
      g_free (agent->stun_server_ip);
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
      g_free (agent->proxy_ip);
      agent->proxy_ip = g_value_dup_string (value);
      break;

    case PROP_PROXY_PORT:
      agent->proxy_port = g_value_get_uint (value);
      break;

    case PROP_PROXY_TYPE:
      agent->proxy_type = g_value_get_uint (value);
      break;

    case PROP_PROXY_USERNAME:
      g_free (agent->proxy_username);
      agent->proxy_username = g_value_dup_string (value);
      break;

    case PROP_PROXY_PASSWORD:
      g_free (agent->proxy_password);
      agent->proxy_password = g_value_dup_string (value);
      break;

    case PROP_UPNP_TIMEOUT:
#ifdef HAVE_GUPNP
      agent->upnp_timeout = g_value_get_uint (value);
#endif
      break;

    case PROP_UPNP:
#ifdef HAVE_GUPNP
      agent->upnp_enabled = g_value_get_boolean (value);
#endif
      break;

    case PROP_RELIABLE:
      agent->reliable = g_value_get_boolean (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  agent_unlock_and_emit (agent);

}

static void priv_pseudo_tcp_error (NiceAgent *agent, Stream *stream,
    Component *component)
{
  if (component->tcp_writable_cancellable) {
    g_cancellable_cancel (component->tcp_writable_cancellable);
    g_clear_object (&component->tcp_writable_cancellable);
  }

  if (component->tcp) {
    agent_signal_component_state_change (agent, stream->id,
        component->id, NICE_COMPONENT_STATE_FAILED);
    component_detach_all_sockets (component);
    pseudo_tcp_socket_close (component->tcp, TRUE);
    g_clear_object (&component->tcp);
  }

  if (component->tcp_clock) {
    g_source_destroy (component->tcp_clock);
    g_source_unref (component->tcp_clock);
    component->tcp_clock = NULL;
  }
}

static void
adjust_tcp_clock (NiceAgent *agent, Stream *stream, Component *component);


static void
pseudo_tcp_socket_opened (PseudoTcpSocket *sock, gpointer user_data)
{
  Component *component = user_data;
  NiceAgent *agent = component->agent;
  Stream *stream = component->stream;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket Opened", agent,
      stream->id, component->id);
  g_cancellable_cancel (component->tcp_writable_cancellable);

  agent_queue_signal (agent, signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE],
      stream->id, component->id);
}

/* Will attempt to queue all @n_messages into the pseudo-TCP transmission
 * buffer. This is always used in reliable mode, so essentially treats @messages
 * as a massive flat array of buffers.
 *
 * Returns the number of messages successfully sent on success (which may be
 * zero if sending the first buffer of the message would have blocked), or
 * a negative number on error. If "allow_partial" is TRUE, then it returns
 * the number of bytes sent
 */
static gint
pseudo_tcp_socket_send_messages (PseudoTcpSocket *self,
    const NiceOutputMessage *messages, guint n_messages, gboolean allow_partial,
    GError **error)
{
  guint i;
  gint bytes_sent = 0;

  for (i = 0; i < n_messages; i++) {
    const NiceOutputMessage *message = &messages[i];
    guint j;

    /* If allow_partial is FALSE and there’s not enough space for the
     * entire message, bail now before queuing anything. This doesn’t
     * gel with the fact this function is only used in reliable mode,
     * and there is no concept of a ‘message’, but is necessary
     * because the calling API has no way of returning to the client
     * and indicating that a message was partially sent. */
    if (!allow_partial &&
        output_message_get_size (message) >
        pseudo_tcp_socket_get_available_send_space (self)) {
      return i;
    }

    for (j = 0;
         (message->n_buffers >= 0 && j < (guint) message->n_buffers) ||
         (message->n_buffers < 0 && message->buffers[j].buffer != NULL);
         j++) {
      const GOutputVector *buffer = &message->buffers[j];
      gssize ret;

      /* Send on the pseudo-TCP socket. */
      ret = pseudo_tcp_socket_send (self, buffer->buffer, buffer->size);

      /* In case of -1, the error is either EWOULDBLOCK or ENOTCONN, which both
       * need the user to wait for the reliable-transport-writable signal */
      if (ret < 0) {
        if (pseudo_tcp_socket_get_error (self) == EWOULDBLOCK)
          goto out;

        if (pseudo_tcp_socket_get_error (self) == ENOTCONN)
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
              "TCP connection is not yet established.");
        else
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
            "Error writing data to pseudo-TCP socket.");
        return -1;
      } else {
        bytes_sent += ret;
      }
    }
  }

 out:

  return allow_partial ? bytes_sent : (gint) i;
}

/* Will fill up @messages from the first free byte onwards (as determined using
 * @iter). This is always used in reliable mode, so it essentially treats
 * @messages as a massive flat array of buffers.
 *
 * Updates @iter in place. @iter and @messages are left in invalid states if
 * an error is returned.
 *
 * Returns the number of valid messages in @messages on success (which may be
 * zero if reading into the first buffer of the message would have blocked), or
 * a negative number on error. */
static gint
pseudo_tcp_socket_recv_messages (PseudoTcpSocket *self,
    NiceInputMessage *messages, guint n_messages, NiceInputMessageIter *iter,
    GError **error)
{
  for (; iter->message < n_messages; iter->message++) {
    NiceInputMessage *message = &messages[iter->message];

    if (iter->buffer == 0 && iter->offset == 0) {
      message->length = 0;
    }

    for (;
         (message->n_buffers >= 0 && iter->buffer < (guint) message->n_buffers) ||
         (message->n_buffers < 0 && message->buffers[iter->buffer].buffer != NULL);
         iter->buffer++) {
      GInputVector *buffer = &message->buffers[iter->buffer];

      do {
        gssize len;

        len = pseudo_tcp_socket_recv (self,
            (gchar *) buffer->buffer + iter->offset,
            buffer->size - iter->offset);

        nice_debug ("%s: Received %" G_GSSIZE_FORMAT " bytes into "
            "buffer %p (offset %" G_GSIZE_FORMAT ", length %" G_GSIZE_FORMAT
            ").", G_STRFUNC, len, buffer->buffer, iter->offset, buffer->size);

        if (len < 0 && pseudo_tcp_socket_get_error (self) == EWOULDBLOCK) {
          len = 0;
          goto done;
        } else if (len < 0 && pseudo_tcp_socket_get_error (self) == ENOTCONN) {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
              "Error reading data from pseudo-TCP socket: not connected.");
          return len;
        } else if (len < 0) {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
              "Error reading data from pseudo-TCP socket.");
          return len;
        } else {
          /* Got some data! */
          message->length += len;
          iter->offset += len;
        }
      } while (iter->offset < buffer->size);

      iter->offset = 0;
    }

    iter->buffer = 0;
  }

done:
  return nice_input_message_iter_get_n_valid_messages (iter);
}

/* This is called with the agent lock held. */
static void
pseudo_tcp_socket_readable (PseudoTcpSocket *sock, gpointer user_data)
{
  Component *component = user_data;
  NiceAgent *agent = component->agent;
  Stream *stream = component->stream;
  gboolean has_io_callback;
  guint stream_id = stream->id;
  guint component_id = component->id;

  g_object_ref (agent);

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket readable", agent,
      stream->id, component->id);

  component->tcp_readable = TRUE;

  has_io_callback = component_has_io_callback (component);

  /* Only dequeue pseudo-TCP data if we can reliably inform the client. The
   * agent lock is held here, so has_io_callback can only change during
   * component_emit_io_callback(), after which it’s re-queried. This ensures
   * no data loss of packets already received and dequeued. */
  if (has_io_callback) {
    do {
      guint8 buf[MAX_BUFFER_SIZE];
      gssize len;

      /* FIXME: Why copy into a temporary buffer here? Why can’t the I/O
       * callbacks be emitted directly from the pseudo-TCP receive buffer? */
      len = pseudo_tcp_socket_recv (sock, (gchar *) buf, sizeof(buf));

      nice_debug ("%s: I/O callback case: Received %" G_GSSIZE_FORMAT " bytes",
          G_STRFUNC, len);

      if (len == 0) {
        component->tcp_readable = FALSE;
        break;
      } else if (len <= 0) {
        /* Handle errors. */
        if (pseudo_tcp_socket_get_error (sock) != EWOULDBLOCK) {
          nice_debug ("%s: calling priv_pseudo_tcp_error()", G_STRFUNC);
          priv_pseudo_tcp_error (agent, stream, component);

          if (component->recv_buf_error != NULL) {
            GIOErrorEnum error_code;

            if (pseudo_tcp_socket_get_error (sock) == ENOTCONN)
              error_code = G_IO_ERROR_BROKEN_PIPE;
            else
              error_code = G_IO_ERROR_FAILED;

            g_set_error (component->recv_buf_error, G_IO_ERROR, error_code,
                "Error reading data from pseudo-TCP socket.");
          }
        }

        break;
      }

      component_emit_io_callback (component, buf, len);

      if (!agent_find_component (agent, stream_id, component_id,
              &stream, &component)) {
        nice_debug ("Stream or Component disappeared during the callback");
        goto out;
      }
      if (!component->tcp) {
        nice_debug ("PseudoTCP socket got destroyed in readable callback!");
        goto out;
      }

      has_io_callback = component_has_io_callback (component);
    } while (has_io_callback);
  } else if (component->recv_messages != NULL) {
    gint n_valid_messages;

    /* Fill up every buffer in every message until the connection closes or an
     * error occurs. Copy the data directly into the client’s receive message
     * array without making any callbacks. Update component->recv_messages_iter
     * as we go. */
    n_valid_messages = pseudo_tcp_socket_recv_messages (sock,
        component->recv_messages, component->n_recv_messages,
        &component->recv_messages_iter, component->recv_buf_error);

    nice_debug ("%s: Client buffers case: Received %d valid messages:",
        G_STRFUNC, n_valid_messages);
    nice_debug_input_message_composition (component->recv_messages,
        component->n_recv_messages);

    if (n_valid_messages < 0) {
      nice_debug ("%s: calling priv_pseudo_tcp_error()", G_STRFUNC);
      priv_pseudo_tcp_error (agent, stream, component);
    } else if (n_valid_messages == 0) {
      component->tcp_readable = FALSE;
    }
  } else {
    nice_debug ("%s: no data read", G_STRFUNC);
  }

  if (stream && component)
    adjust_tcp_clock (agent, stream, component);

out:

  g_object_unref (agent);

}

static void
pseudo_tcp_socket_writable (PseudoTcpSocket *sock, gpointer user_data)
{
  Component *component = user_data;
  NiceAgent *agent = component->agent;
  Stream *stream = component->stream;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket writable", agent,
      stream->id, component->id);
  g_cancellable_cancel (component->tcp_writable_cancellable);
  agent_queue_signal (agent, signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE],
      stream->id, component->id);
}

static void
pseudo_tcp_socket_closed (PseudoTcpSocket *sock, guint32 err,
    gpointer user_data)
{
  Component *component = user_data;
  NiceAgent *agent = component->agent;
  Stream *stream = component->stream;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket closed. "
      "Calling priv_pseudo_tcp_error().",  agent, stream->id, component->id);
  priv_pseudo_tcp_error (agent, stream, component);
}


static PseudoTcpWriteResult
pseudo_tcp_socket_write_packet (PseudoTcpSocket *socket,
    const gchar *buffer, guint32 len, gpointer user_data)
{
  Component *component = user_data;

  if (component->selected_pair.local != NULL) {
    NiceSocket *sock;
    NiceAddress *addr;

    sock = component->selected_pair.local->sockptr;

    if (nice_debug_is_enabled ()) {
      gchar tmpbuf[INET6_ADDRSTRLEN];
      nice_address_to_string (&component->selected_pair.remote->addr, tmpbuf);

      nice_debug (
          "Agent %p : s%d:%d: sending %d bytes on socket %p (FD %d) to [%s]:%d",
          component->agent, component->stream->id, component->id, len,
          sock->fileno, g_socket_get_fd (sock->fileno), tmpbuf,
          nice_address_get_port (&component->selected_pair.remote->addr));
    }

    addr = &component->selected_pair.remote->addr;

    if (nice_socket_send (sock, addr, len, buffer))
      return WR_SUCCESS;
  } else {
    nice_debug ("%s: WARNING: Failed to send pseudo-TCP packet from agent %p "
        "as no pair has been selected yet.", G_STRFUNC, component->agent);
  }

  return WR_FAIL;
}


static gboolean
notify_pseudo_tcp_socket_clock (gpointer user_data)
{
  Component *component = user_data;
  Stream *stream = component->stream;
  NiceAgent *agent = component->agent;

  agent_lock();

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in notify_pseudo_tcp_socket_clock");
    agent_unlock ();
    return FALSE;
  }

  pseudo_tcp_socket_notify_clock (component->tcp);
  adjust_tcp_clock (agent, stream, component);

  agent_unlock_and_emit (agent);

  return G_SOURCE_CONTINUE;
}

static void
adjust_tcp_clock (NiceAgent *agent, Stream *stream, Component *component)
{
  if (component->tcp) {
    long timeout = component->last_clock_timeout;

    if (pseudo_tcp_socket_get_next_clock (component->tcp, &timeout)) {
      if (timeout != component->last_clock_timeout) {
        component->last_clock_timeout = timeout;
        if (component->tcp_clock) {
#if GLIB_CHECK_VERSION (2, 36, 0)
          g_source_set_ready_time (component->tcp_clock, timeout * 1000);
#else
          g_source_destroy (component->tcp_clock);
          g_source_unref (component->tcp_clock);
          component->tcp_clock = NULL;
#endif
        }
        if (!component->tcp_clock) {
          long interval = timeout - (g_get_monotonic_time () / 1000);

          /* Prevent integer overflows */
          if (interval < 0 || interval > G_MAXINT)
            interval = 0;
          component->tcp_clock = agent_timeout_add_with_context (agent, interval,
              notify_pseudo_tcp_socket_clock, component);
        }
      }
    } else {
      nice_debug ("Agent %p: component %d pseudo-TCP socket should be "
          "destroyed. Calling priv_pseudo_tcp_error().",
          agent, component->id);
      priv_pseudo_tcp_error (agent, stream, component);
    }
  }
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
	if (nice_debug_is_enabled ()) {
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

#ifdef HAVE_GUPNP
  if (agent->discovery_timer_source == NULL &&
      agent->upnp_timer_source == NULL) {
    agent_signal_gathering_done (agent);
  }
#else
  if (agent->discovery_timer_source == NULL)
    agent_signal_gathering_done (agent);
#endif
}

void agent_signal_gathering_done (NiceAgent *agent)
{
  GSList *i;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    if (stream->gathering) {
      stream->gathering = FALSE;
      agent_queue_signal (agent, signals[SIGNAL_CANDIDATE_GATHERING_DONE],
          stream->id);
    }
  }
}

void agent_signal_initial_binding_request_received (NiceAgent *agent, Stream *stream)
{
  if (stream->initial_binding_request_received != TRUE) {
    stream->initial_binding_request_received = TRUE;
    agent_queue_signal (agent, signals[SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED],
        stream->id);
  }
}

/* If the Component now has a selected_pair, and has pending TCP packets which
 * it couldn’t receive before due to not being able to send out ACKs (or
 * SYNACKs, for the initial SYN packet), handle them now.
 *
 * Must be called with the agent lock held. */
static void
process_queued_tcp_packets (NiceAgent *agent, Stream *stream,
    Component *component)
{
  GOutputVector *vec;
  guint stream_id = stream->id;
  guint component_id = component->id;

  if (component->selected_pair.local == NULL || component->tcp == NULL)
    return;

  nice_debug ("%s: Sending outstanding packets for agent %p.", G_STRFUNC,
      agent);

  while ((vec = g_queue_peek_head (&component->queued_tcp_packets)) != NULL) {
    gboolean retval;

    nice_debug ("%s: Sending %" G_GSIZE_FORMAT " bytes.", G_STRFUNC, vec->size);
    retval =
        pseudo_tcp_socket_notify_packet (component->tcp, vec->buffer,
            vec->size);

    if (!agent_find_component (agent, stream_id, component_id,
            &stream, &component)) {
      nice_debug ("Stream or Component disappeared during "
          "pseudo_tcp_socket_notify_packet()");
      return;
    }
    if (!component->tcp) {
      nice_debug ("PseudoTCP socket got destroyed in"
          " pseudo_tcp_socket_notify_packet()!");
      return;
    }

    adjust_tcp_clock (agent, stream, component);

    if (!retval) {
      /* Failed to send; try again later. */
      break;
    }

    g_queue_pop_head (&component->queued_tcp_packets);
    g_free ((gpointer) vec->buffer);
    g_slice_free (GOutputVector, vec);
  }
}

void agent_signal_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, const gchar *local_foundation, const gchar *remote_foundation)
{
  Component *component;
  Stream *stream;
  gchar *lf_copy;
  gchar *rf_copy;

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    return;

  if (component->selected_pair.local->type == NICE_CANDIDATE_TYPE_RELAYED) {
    nice_turn_socket_set_peer (component->selected_pair.local->sockptr,
                                   &component->selected_pair.remote->addr);
  }

  if (component->tcp) {
    process_queued_tcp_packets (agent, stream, component);

    pseudo_tcp_socket_connect (component->tcp);
    pseudo_tcp_socket_notify_mtu (component->tcp, MAX_TCP_MTU);
    adjust_tcp_clock (agent, stream, component);
  } else if(agent->reliable) {
    nice_debug ("New selected pair received when pseudo tcp socket in error");
    return;
  }

  lf_copy = g_strdup (local_foundation);
  rf_copy = g_strdup (remote_foundation);

  agent_queue_signal (agent, signals[SIGNAL_NEW_SELECTED_PAIR],
      stream_id, component_id, lf_copy, rf_copy);

  g_free (lf_copy);
  g_free (rf_copy);
}

void agent_signal_new_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  agent_queue_signal (agent, signals[SIGNAL_NEW_CANDIDATE],
      candidate->stream_id, candidate->component_id, candidate->foundation);
}

void agent_signal_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  agent_queue_signal (agent, signals[SIGNAL_NEW_REMOTE_CANDIDATE],
      candidate->stream_id, candidate->component_id, candidate->foundation);
}

static const gchar *
component_state_to_string (NiceComponentState state)
{
  switch (state)
    {
      case NICE_COMPONENT_STATE_DISCONNECTED:
        return "disconnected";
      case NICE_COMPONENT_STATE_GATHERING:
        return "gathering";
      case NICE_COMPONENT_STATE_CONNECTING:
        return "connecting";
      case NICE_COMPONENT_STATE_CONNECTED:
        return "connected";
      case NICE_COMPONENT_STATE_READY:
        return "ready";
      case NICE_COMPONENT_STATE_FAILED:
        return "failed";
      case NICE_COMPONENT_STATE_LAST:
      default:
        return "invalid";
    }
}

void agent_signal_component_state_change (NiceAgent *agent, guint stream_id, guint component_id, NiceComponentState state)
{
  Component *component;
  Stream *stream;

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    return;

  if (agent->reliable && component->tcp == NULL &&
      state != NICE_COMPONENT_STATE_FAILED) {
    nice_debug ("Agent %p: not changing component state for s%d:%d to %d "
        "because pseudo tcp socket does not exist in reliable mode", agent,
        stream->id, component->id, state);
    return;
  }

  if (component->state != state && state < NICE_COMPONENT_STATE_LAST) {
    nice_debug ("Agent %p : stream %u component %u STATE-CHANGE %s -> %s.", agent,
        stream_id, component_id, component_state_to_string (component->state),
        component_state_to_string (state));

    component->state = state;

    process_queued_tcp_packets (agent, stream, component);

    agent_queue_signal (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED],
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

static void
priv_add_new_candidate_discovery_stun (NiceAgent *agent,
    NiceSocket *socket, NiceAddress server,
    Stream *stream, guint component_id)
{
  CandidateDiscovery *cdisco;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);

  cdisco->type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
  cdisco->nicesock = socket;
  cdisco->server = server;
  cdisco->stream = stream;
  cdisco->component = stream_find_component_by_id (stream, component_id);
  cdisco->agent = agent;
  stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC3489,
      (agent->compatibility == NICE_COMPATIBILITY_OC2007 ||
       agent->compatibility == NICE_COMPATIBILITY_OC2007R2) ?
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES : 0);

  nice_debug ("Agent %p : Adding new srv-rflx candidate discovery %p\n",
      agent, cdisco);

  agent->discovery_list = g_slist_append (agent->discovery_list, cdisco);
  ++agent->discovery_unsched_items;
}

static void
priv_add_new_candidate_discovery_turn (NiceAgent *agent,
    NiceSocket *socket, TurnServer *turn,
    Stream *stream, guint component_id)
{
  CandidateDiscovery *cdisco;
  Component *component = stream_find_component_by_id (stream, component_id);

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);
  cdisco->type = NICE_CANDIDATE_TYPE_RELAYED;

  if (turn->type ==  NICE_RELAY_TYPE_TURN_UDP) {
    if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
      NiceAddress addr = socket->addr;
      NiceSocket *new_socket;
      nice_address_set_port (&addr, 0);

      new_socket = nice_udp_bsd_socket_new (&addr);
      if (new_socket) {
        _priv_set_socket_tos (agent, new_socket, stream->tos);
        component_attach_socket (component, new_socket);
        socket = new_socket;
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
      socket = nice_tcp_bsd_socket_new (agent->main_context, &proxy_server);

      if (socket) {
        _priv_set_socket_tos (agent, socket, stream->tos);
        if (agent->proxy_type == NICE_PROXY_TYPE_SOCKS5) {
          socket = nice_socks5_socket_new (socket, &turn->server,
              agent->proxy_username, agent->proxy_password);
        } else if (agent->proxy_type == NICE_PROXY_TYPE_HTTP){
          socket = nice_http_socket_new (socket, &turn->server,
              agent->proxy_username, agent->proxy_password);
        } else {
          nice_socket_free (socket);
          socket = NULL;
        }
      }

    }
    if (socket == NULL) {
      socket = nice_tcp_bsd_socket_new (agent->main_context, &turn->server);

      if (socket)
        _priv_set_socket_tos (agent, socket, stream->tos);
    }

    /* The TURN server may be invalid or not listening */
    if (socket == NULL)
      return;

    if (turn->type ==  NICE_RELAY_TYPE_TURN_TLS &&
        agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
      socket = nice_pseudossl_socket_new (socket);
    }
    cdisco->nicesock = nice_tcp_turn_socket_new (socket,
        agent_to_turn_socket_compatibility (agent));

    component_attach_socket (component, cdisco->nicesock);
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
  } else if (agent->compatibility == NICE_COMPATIBILITY_OC2007 ||
      agent->compatibility == NICE_COMPATIBILITY_OC2007R2) {
    stun_agent_init (&cdisco->stun_agent, STUN_MSOC_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_OC2007,
        STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
  } else {
    stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC5389,
        STUN_AGENT_USAGE_ADD_SOFTWARE |
        STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS);
  }
  stun_agent_set_software (&cdisco->stun_agent, agent->software_attribute);

  nice_debug ("Agent %p : Adding new relay-rflx candidate discovery %p\n",
      agent, cdisco);
  agent->discovery_list = g_slist_append (agent->discovery_list, cdisco);
  ++agent->discovery_unsched_items;
}

NICEAPI_EXPORT guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components)
{
  Stream *stream;
  guint ret = 0;
  guint i;

  agent_lock();
  stream = stream_new (n_components, agent);

  agent->streams = g_slist_append (agent->streams, stream);
  stream->id = agent->next_stream_id++;
  nice_debug ("Agent %p : allocating stream id %u (%p)", agent, stream->id, stream);
  if (agent->reliable) {
    nice_debug ("Agent %p : reliable stream", agent);
    for (i = 0; i < n_components; i++) {
      Component *component = stream_find_component_by_id (stream, i + 1);
      if (component) {
        PseudoTcpCallbacks tcp_callbacks = {component,
                                            pseudo_tcp_socket_opened,
                                            pseudo_tcp_socket_readable,
                                            pseudo_tcp_socket_writable,
                                            pseudo_tcp_socket_closed,
                                            pseudo_tcp_socket_write_packet};
        component->tcp = pseudo_tcp_socket_new (0, &tcp_callbacks);
        component->tcp_writable_cancellable = g_cancellable_new ();
        adjust_tcp_clock (agent, stream, component);
        nice_debug ("Agent %p: Create Pseudo Tcp Socket for component %d",
            agent, i+1);
      } else {
        nice_debug ("Agent %p: couldn't find component %d", agent, i+1);
      }
    }
  }

  stream_initialize_credentials (stream, agent->rng);

  ret = stream->id;

  agent_unlock_and_emit (agent);
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
  g_return_val_if_fail (type <= NICE_RELAY_TYPE_TURN_TLS, FALSE);

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    TurnServer *turn = g_slice_new0 (TurnServer);
    nice_address_init (&turn->server);

    if (nice_address_set_from_string (&turn->server, server_ip)) {
      nice_address_set_port (&turn->server, server_port);
    } else {
      g_slice_free (TurnServer, turn);
      agent_unlock_and_emit (agent);
      return FALSE;
    }


    turn->username = g_strdup (username);
    turn->password = g_strdup (password);
    turn->type = type;

    nice_debug ("Agent %p: added relay server [%s]:%d of type %d", agent,
        server_ip, server_port, type);

    component->turn_servers = g_list_append (component->turn_servers, turn);
  }

  agent_unlock_and_emit (agent);
  return TRUE;
}

#ifdef HAVE_GUPNP

static gboolean priv_upnp_timeout_cb (gpointer user_data)
{
  NiceAgent *agent = (NiceAgent*)user_data;
  GSList *i;

  agent_lock();

  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock ();
    return FALSE;
  }

  nice_debug ("Agent %p : UPnP port mapping timed out", agent);

  for (i = agent->upnp_mapping; i; i = i->next) {
    NiceAddress *a = i->data;
    nice_address_free (a);
  }
  g_slist_free (agent->upnp_mapping);
  agent->upnp_mapping = NULL;

  if (agent->upnp_timer_source != NULL) {
    g_source_destroy (agent->upnp_timer_source);
    g_source_unref (agent->upnp_timer_source);
    agent->upnp_timer_source = NULL;
  }

  agent_gathering_done (agent);

  agent_unlock_and_emit (agent);
  return FALSE;
}

static void _upnp_mapped_external_port (GUPnPSimpleIgd *self, gchar *proto,
    gchar *external_ip, gchar *replaces_external_ip, guint external_port,
    gchar *local_ip, guint local_port, gchar *description, gpointer user_data)
{
  NiceAgent *agent = (NiceAgent*)user_data;
  NiceAddress localaddr;
  NiceAddress externaddr;

  GSList *i, *j, *k;

  agent_lock();

  nice_debug ("Agent %p : Successfully mapped %s:%d to %s:%d", agent, local_ip,
      local_port, external_ip, external_port);

  if (!nice_address_set_from_string (&localaddr, local_ip))
    goto end;
  nice_address_set_port (&localaddr, local_port);

  for (i = agent->upnp_mapping; i; i = i->next) {
    NiceAddress *addr = i->data;
    if (nice_address_equal (&localaddr, addr)) {
      agent->upnp_mapping = g_slist_remove (agent->upnp_mapping, addr);
      nice_address_free (addr);
      break;
    }
  }

  if (!nice_address_set_from_string (&externaddr, external_ip))
    goto end;
  nice_address_set_port (&externaddr, external_port);

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *component = j->data;
      for (k = component->local_candidates; k; k = k->next) {
        NiceCandidate *local_candidate = k->data;

        if (nice_address_equal (&localaddr, &local_candidate->base_addr)) {
          discovery_add_server_reflexive_candidate (
              agent,
              stream->id,
              component->id,
              &externaddr,
              local_candidate->sockptr);
          goto end;
        }
      }
    }
  }

 end:
  if (g_slist_length (agent->upnp_mapping) == 0) {
    if (agent->upnp_timer_source != NULL) {
      g_source_destroy (agent->upnp_timer_source);
      g_source_unref (agent->upnp_timer_source);
      agent->upnp_timer_source = NULL;
    }
    agent_gathering_done (agent);
  }

  agent_unlock_and_emit (agent);
}

static void _upnp_error_mapping_port (GUPnPSimpleIgd *self, GError *error,
    gchar *proto, guint external_port, gchar *local_ip, guint local_port,
    gchar *description, gpointer user_data)
{
  NiceAgent *agent = (NiceAgent*)user_data;
  NiceAddress localaddr;
  GSList *i;

  agent_lock();

  nice_debug ("Agent %p : Error mapping %s:%d to %d (%d) : %s", agent, local_ip,
      local_port, external_port, error->domain, error->message);
  if (nice_address_set_from_string (&localaddr, local_ip)) {
    nice_address_set_port (&localaddr, local_port);

    for (i = agent->upnp_mapping; i; i = i->next) {
      NiceAddress *addr = i->data;
      if (nice_address_equal (&localaddr, addr)) {
        agent->upnp_mapping = g_slist_remove (agent->upnp_mapping, addr);
        nice_address_free (addr);
        break;
      }
    }

    if (g_slist_length (agent->upnp_mapping) == 0) {
      if (agent->upnp_timer_source != NULL) {
        g_source_destroy (agent->upnp_timer_source);
        g_source_unref (agent->upnp_timer_source);
        agent->upnp_timer_source = NULL;
      }
      agent_gathering_done (agent);
    }
  }

  agent_unlock_and_emit (agent);
}

#endif

NICEAPI_EXPORT gboolean
nice_agent_gather_candidates (
  NiceAgent *agent,
  guint stream_id)
{
  guint n;
  GSList *i;
  Stream *stream;
  GSList *local_addresses = NULL;
  gboolean ret = TRUE;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    agent_unlock_and_emit (agent);
    return FALSE;
  }

  nice_debug ("Agent %p : In %s mode, starting candidate gathering.", agent,
      agent->full_mode ? "ICE-FULL" : "ICE-LITE");

#ifdef HAVE_GUPNP
  priv_free_upnp (agent);

  if (agent->upnp_enabled) {
    agent->upnp = gupnp_simple_igd_thread_new ();

    agent->upnp_timer_source = agent_timeout_add_with_context (agent,
        agent->upnp_timeout, priv_upnp_timeout_cb, agent);

    if (agent->upnp) {
      g_signal_connect (agent->upnp, "mapped-external-port",
          G_CALLBACK (_upnp_mapped_external_port), agent);
      g_signal_connect (agent->upnp, "error-mapping-port",
          G_CALLBACK (_upnp_error_mapping_port), agent);
    } else {
      nice_debug ("Agent %p : Error creating UPnP Simple IGD agent", agent);
    }
  } else {
    nice_debug ("Agent %p : UPnP property Disabled", agent);
  }
#else
  nice_debug ("Agent %p : libnice compiled without UPnP support", agent);
#endif

  /* if no local addresses added, generate them ourselves */
  if (agent->local_addresses == NULL) {
    GList *addresses = nice_interfaces_get_local_ips (FALSE);
    GList *item;

    for (item = addresses; item; item = g_list_next (item)) {
      NiceAddress *addr = nice_address_new ();

      if (nice_address_set_from_string (addr, item->data)) {
        local_addresses = g_slist_append (local_addresses, addr);
      } else {
        nice_address_free (addr);
      }
    }

    g_list_foreach (addresses, (GFunc) g_free, NULL);
    g_list_free (addresses);
  } else {
    for (i = agent->local_addresses; i; i = i->next) {
      NiceAddress *addr = i->data;
      NiceAddress *dup = nice_address_dup (addr);

      local_addresses = g_slist_append (local_addresses, dup);
    }
  }

  /* generate a local host candidate for each local address */
  for (i = local_addresses; i; i = i->next) {
    NiceAddress *addr = i->data;
    NiceCandidate *host_candidate;

#ifdef HAVE_GUPNP
    gchar local_ip[NICE_ADDRESS_STRING_LEN];
    nice_address_to_string (addr, local_ip);
#endif

    for (n = 0; n < stream->n_components; n++) {
      Component *component = stream_find_component_by_id (stream, n + 1);
      guint current_port;
      guint start_port;

      if (component == NULL)
        continue;

      start_port = component->min_port;
      if(component->min_port != 0) {
        start_port = nice_rng_generate_int(agent->rng, component->min_port, component->max_port+1);
      }
      current_port = start_port;

      if (agent->reliable && component->tcp == NULL) {
        nice_debug ("Agent %p: not gathering candidates for s%d:%d because "
            "pseudo tcp socket does not exist in reliable mode", agent,
            stream->id, component->id);
        continue;
      }

      host_candidate = NULL;
      while (host_candidate == NULL) {
        nice_debug ("Agent %p: Trying to create host candidate on port %d", agent, current_port);
        nice_address_set_port (addr, current_port);
        host_candidate = discovery_add_local_host_candidate (agent, stream->id,
            n + 1, addr);
        if (current_port > 0)
          current_port++;
        if (current_port > component->max_port) current_port = component->min_port;
        if (current_port == 0 || current_port == start_port)
          break;
      }
      nice_address_set_port (addr, 0);

      if (!host_candidate) {
        if (nice_debug_is_enabled ()) {
          gchar ip[NICE_ADDRESS_STRING_LEN];
          nice_address_to_string (addr, ip);
          nice_debug ("Agent %p: Unable to add local host candidate %s for"
              " s%d:%d. Invalid interface?", agent, ip, stream->id,
              component->id);
        }
        ret = FALSE;
        goto error;
      }

#ifdef HAVE_GUPNP
      if (agent->upnp_enabled) {
        NiceAddress *base_addr = nice_address_dup (&host_candidate->base_addr);
        nice_debug ("Agent %p: Adding UPnP port %s:%d", agent, local_ip,
            nice_address_get_port (base_addr));
        gupnp_simple_igd_add_port (GUPNP_SIMPLE_IGD (agent->upnp), "UDP",
            0, local_ip, nice_address_get_port (base_addr),
            0, PACKAGE_STRING);
        agent->upnp_mapping = g_slist_prepend (agent->upnp_mapping, base_addr);
      }
#endif

      if (agent->full_mode &&
          agent->stun_server_ip) {
        NiceAddress stun_server;
        if (nice_address_set_from_string (&stun_server, agent->stun_server_ip)) {
          nice_address_set_port (&stun_server, agent->stun_server_port);

          priv_add_new_candidate_discovery_stun (agent,
              host_candidate->sockptr,
              stun_server,
              stream,
              n + 1);
        }
      }

      if (agent->full_mode && component) {
        GList *item;

        for (item = component->turn_servers; item; item = item->next) {
          TurnServer *turn = item->data;

          priv_add_new_candidate_discovery_turn (agent,
              host_candidate->sockptr,
              turn,
              stream,
              n + 1);
        }
      }
    }
  }

  stream->gathering = TRUE;


  /* Only signal the new candidates after we're sure that the gathering was
   * succesfful. But before sending gathering-done */
  for (n = 0; n < stream->n_components; n++) {
    Component *component = stream_find_component_by_id (stream, n + 1);
    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *candidate = i->data;
      agent_signal_new_candidate (agent, candidate);
    }
  }

  /* note: no async discoveries pending, signal that we are ready */
  if (agent->discovery_unsched_items == 0 &&
#ifdef HAVE_GUPNP
      g_slist_length (agent->upnp_mapping) == 0) {
#else
      TRUE) {
#endif
    nice_debug ("Agent %p: Candidate gathering FINISHED, no scheduled items.",
        agent);
    agent_gathering_done (agent);
  } else if (agent->discovery_unsched_items) {
    discovery_schedule (agent);
  }

 error:
  for (i = local_addresses; i; i = i->next)
    nice_address_free (i->data);
  g_slist_free (local_addresses);

  if (ret == FALSE) {
    priv_free_upnp (agent);
    for (n = 0; n < stream->n_components; n++) {
      Component *component = stream_find_component_by_id (stream, n + 1);

      component_free_socket_sources (component);

      for (i = component->local_candidates; i; i = i->next) {
        NiceCandidate *candidate = i->data;
        nice_candidate_free (candidate);
      }
      g_slist_free (component->local_candidates);
      component->local_candidates = NULL;
    }
    discovery_prune_stream (agent, stream_id);
  }

  agent_unlock_and_emit (agent);

  return ret;
}

static void priv_free_upnp (NiceAgent *agent)
{
#ifdef HAVE_GUPNP
  GSList *i;

  if (agent->upnp) {
    g_object_unref (agent->upnp);
    agent->upnp = NULL;
  }

  for (i = agent->upnp_mapping; i; i = i->next) {
    NiceAddress *a = i->data;
    nice_address_free (a);
  }
  g_slist_free (agent->upnp_mapping);
  agent->upnp_mapping = NULL;

  if (agent->upnp_timer_source != NULL) {
    g_source_destroy (agent->upnp_timer_source);
    g_source_unref (agent->upnp_timer_source);
    agent->upnp_timer_source = NULL;
  }
#endif
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
  guint stream_ids[] = { stream_id, 0 };

  /* note that streams/candidates can be in use by other threads */

  Stream *stream;

  agent_lock();
  stream = agent_find_stream (agent, stream_id);

  if (!stream) {
    agent_unlock_and_emit (agent);
    return;
  }

  /* note: remove items with matching stream_ids from both lists */
  conn_check_prune_stream (agent, stream);
  discovery_prune_stream (agent, stream_id);
  refresh_prune_stream (agent, stream_id);

  /* Remove the stream and signal its removal. */
  agent->streams = g_slist_remove (agent->streams, stream);
  stream_free (stream);

  if (!agent->streams)
    priv_remove_keepalive_timer (agent);

  agent_queue_signal (agent, signals[SIGNAL_STREAMS_REMOVED], stream_ids);

  agent_unlock_and_emit (agent);
  return;
}

NICEAPI_EXPORT void
nice_agent_set_port_range (NiceAgent *agent, guint stream_id, guint component_id,
    guint min_port, guint max_port)
{
  Component *component;

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    component->min_port = min_port;
    component->max_port = max_port;
  }

  agent_unlock_and_emit (agent);
}

NICEAPI_EXPORT gboolean
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr)
{
  NiceAddress *dup;

  agent_lock();

  dup = nice_address_dup (addr);
  nice_address_set_port (dup, 0);
  agent->local_addresses = g_slist_append (agent->local_addresses, dup);

  agent_unlock_and_emit (agent);
  return TRUE;
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

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return FALSE;

  /* step: check whether the candidate already exists */
  candidate = component_find_remote_candidate(component, addr, transport);
  if (candidate) {
    if (nice_debug_is_enabled ()) {
      gchar tmpbuf[INET6_ADDRSTRLEN];
      nice_address_to_string (addr, tmpbuf);
      nice_debug ("Agent %p : Updating existing remote candidate with addr [%s]:%u"
          " for s%d/c%d. U/P '%s'/'%s' prio: %u", agent, tmpbuf,
          nice_address_get_port (addr), stream_id, component_id,
          username, password, priority);
    }
    /* case 1: an existing candidate, update the attributes */
    candidate->type = type;
    if (base_addr)
      candidate->base_addr = *base_addr;
    candidate->priority = priority;
    if (foundation)
      g_strlcpy(candidate->foundation, foundation,
          NICE_CANDIDATE_MAX_FOUNDATION);
    /* note: username and password must remain the same during
     *       a session; see sect 9.1.2 in ICE ID-19 */

    /* note: however, the user/pass in ID-19 is global, if the user/pass
     * are set in the candidate here, it means they need to be updated...
     * this is essential to overcome a race condition where we might receive
     * a valid binding request from a valid candidate that wasn't yet added to
     * our list of candidates.. this 'update' will make the peer-rflx a
     * server-rflx/host candidate again and restore that user/pass it needed
     * to have in the first place */
    if (username) {
      g_free (candidate->username);
      candidate->username = g_strdup (username);
    }
    if (password) {
      g_free (candidate->password);
      candidate->password = g_strdup (password);
    }
    if (conn_check_add_for_candidate (agent, stream_id, component, candidate) < 0)
      goto errors;
  }
  else {
    /* case 2: add a new candidate */

    candidate = nice_candidate_new (type);
    component->remote_candidates = g_slist_append (component->remote_candidates,
        candidate);

    candidate->stream_id = stream_id;
    candidate->component_id = component_id;

    candidate->type = type;
    if (addr)
      candidate->addr = *addr;

    if (nice_debug_is_enabled ()) {
      gchar tmpbuf[INET6_ADDRSTRLEN] = {0};
      if (addr)
        nice_address_to_string (addr, tmpbuf);
      nice_debug ("Agent %p : Adding remote candidate with addr [%s]:%u"
          " for s%d/c%d. U/P '%s'/'%s' prio: %u", agent, tmpbuf,
          addr? nice_address_get_port (addr) : 0, stream_id, component_id,
          username, password, priority);
    }

    if (base_addr)
      candidate->base_addr = *base_addr;

    candidate->transport = transport;
    candidate->priority = priority;
    candidate->username = g_strdup (username);
    candidate->password = g_strdup (password);

    if (foundation)
      g_strlcpy (candidate->foundation, foundation,
          NICE_CANDIDATE_MAX_FOUNDATION);

    if (conn_check_add_for_candidate (agent, stream_id, component, candidate) < 0)
      goto errors;
  }

  return TRUE;

errors:
  nice_candidate_free (candidate);
  return FALSE;
}

NICEAPI_EXPORT gboolean
nice_agent_set_remote_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar *ufrag, const gchar *pwd)
{
  Stream *stream;
  gboolean ret = FALSE;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  /* note: oddly enough, ufrag and pwd can be empty strings */
  if (stream && ufrag && pwd) {

    g_strlcpy (stream->remote_ufrag, ufrag, NICE_STREAM_MAX_UFRAG);
    g_strlcpy (stream->remote_password, pwd, NICE_STREAM_MAX_PWD);

    ret = TRUE;
    goto done;
  }

 done:
  agent_unlock_and_emit (agent);
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

  agent_lock();

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

  agent_unlock_and_emit (agent);
  return ret;
}

static int
_set_remote_candidates_locked (NiceAgent *agent, Stream *stream,
    Component *component, const GSList *candidates)
{
  const GSList *i;
  int added = 0;

  if (agent->reliable && component->tcp == NULL) {
    nice_debug ("Agent %p: not setting remote candidate for s%d:%d because "
        "pseudo tcp socket does not exist in reliable mode", agent,
        stream->id, component->id);
    goto done;
  }

 for (i = candidates; i && added >= 0; i = i->next) {
   NiceCandidate *d = (NiceCandidate*) i->data;

   if (nice_address_is_valid (&d->addr) == TRUE) {
     gboolean res =
         priv_add_remote_candidate (agent,
             stream->id,
             component->id,
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
   }
 }

 conn_check_remote_candidates_set(agent);

 if (added > 0) {
   gboolean res = conn_check_schedule_next (agent);
   if (res != TRUE)
     nice_debug ("Agent %p : Warning: unable to schedule any conn checks!", agent);
 }

 done:
 return added;
}


NICEAPI_EXPORT int
nice_agent_set_remote_candidates (NiceAgent *agent, guint stream_id, guint component_id, const GSList *candidates)
{
  int added = 0;
  Stream *stream;
  Component *component;

  nice_debug ("Agent %p: set_remote_candidates %d %d", agent, stream_id, component_id);

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component)) {
    g_warning ("Could not find component %u in stream %u", component_id,
        stream_id);
    added = -1;
    goto done;
  }

  added = _set_remote_candidates_locked (agent, stream, component, candidates);

 done:
  agent_unlock_and_emit (agent);

  return added;
}

/* Return values for agent_recv_message_unlocked(). Needed purely because it
 * must differentiate between RECV_OOB and RECV_SUCCESS. */
typedef enum {
  RECV_ERROR = -2,
  RECV_WOULD_BLOCK = -1,
  RECV_OOB = 0,
  RECV_SUCCESS = 1,
} RecvStatus;

/*
 * agent_recv_message_unlocked:
 * @agent: a #NiceAgent
 * @stream: the stream to receive from
 * @component: the component to receive from
 * @socket: the socket to receive on
 * @message: the message to write into (must have at least 65536 bytes of buffer
 * space)
 *
 * Receive a single message of data from the given @stream, @component and
 * @socket tuple, in a non-blocking fashion. The caller must ensure that
 * @message contains enough buffers to provide at least 65536 bytes of buffer
 * space, but the buffers may be split as the caller sees fit.
 *
 * This must be called with the agent’s lock held.
 *
 * Returns: number of valid messages received on success (i.e. %RECV_SUCCESS or
 * 1), %RECV_OOB if data was successfully received but was handled out-of-band
 * (e.g. due to being a STUN control packet), %RECV_WOULD_BLOCK if no data is
 * available and the call would block, or %RECV_ERROR on error
 */
static RecvStatus
agent_recv_message_unlocked (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceSocket *socket,
  NiceInputMessage *message)
{
  NiceAddress from;
  GList *item;
  gint retval;

  /* We need an address for packet parsing, below. */
  if (message->from == NULL) {
    message->from = &from;
  }

  retval = nice_socket_recv_messages (socket, message, 1);

  nice_debug ("%s: Received %d valid messages of length %" G_GSIZE_FORMAT
      " from base socket %p.", G_STRFUNC, retval, message->length, socket);

  if (retval == 0) {
    retval = RECV_WOULD_BLOCK;  /* EWOULDBLOCK */
    goto done;
  } else if (retval < 0) {
    nice_debug ("Agent %p: %s returned %d, errno (%d) : %s",
        agent, G_STRFUNC, retval, errno, g_strerror (errno));

    retval = RECV_ERROR;
    goto done;
  }

  if (nice_debug_is_enabled () && message->length > 0) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (message->from, tmpbuf);
    nice_debug ("Agent %p : Packet received on local socket %d from [%s]:%u (%" G_GSSIZE_FORMAT " octets).", agent,
        g_socket_get_fd (socket->fileno), tmpbuf,
        nice_address_get_port (message->from), message->length);
  }

  for (item = component->turn_servers; item; item = g_list_next (item)) {
    TurnServer *turn = item->data;
    GSList *i = NULL;

    if (!nice_address_equal (message->from, &turn->server))
      continue;

    nice_debug ("Agent %p : Packet received from TURN server candidate.",
        agent);

    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *cand = i->data;

      if (cand->type == NICE_CANDIDATE_TYPE_RELAYED &&
          cand->stream_id == stream->id &&
          cand->component_id == component->id) {
        nice_turn_socket_parse_recv_message (cand->sockptr, &socket, message);
      }
    }
  }

  agent->media_after_tick = TRUE;

  /* If the message’s stated length is equal to its actual length, it’s probably
   * a STUN message; otherwise it’s probably data. */
  if (stun_message_validate_buffer_length_fast (
      (StunInputVector *) message->buffers, message->n_buffers, message->length,
      (agent->compatibility != NICE_COMPATIBILITY_OC2007 &&
       agent->compatibility != NICE_COMPATIBILITY_OC2007R2)) == (ssize_t) message->length) {
    /* Slow path: If this message isn’t obviously *not* a STUN packet, compact
     * its buffers
     * into a single monolithic one and parse the packet properly. */
    guint8 *big_buf;
    gsize big_buf_len;

    big_buf = compact_input_message (message, &big_buf_len);

    if (stun_message_validate_buffer_length (big_buf, big_buf_len,
        (agent->compatibility != NICE_COMPATIBILITY_OC2007 &&
         agent->compatibility != NICE_COMPATIBILITY_OC2007R2)) == (gint) big_buf_len &&
        conn_check_handle_inbound_stun (agent, stream, component, socket,
            message->from, (gchar *) big_buf, big_buf_len)) {
      /* Handled STUN message. */
      nice_debug ("%s: Valid STUN packet received.", G_STRFUNC);

      retval = RECV_OOB;
      g_free (big_buf);
      goto done;
    }

    nice_debug ("%s: WARNING: Packet passed fast STUN validation but failed "
        "slow validation.", G_STRFUNC);

    g_free (big_buf);
  }

  /* Unhandled STUN; try handling TCP data, then pass to the client. */
  if (message->length > 0 && component->tcp) {
    /* If we don’t yet have an underlying selected socket, queue up the incoming
     * data to handle later. This is because we can’t send ACKs (or, more
     * importantly for the first few packets, SYNACKs) without an underlying
     * socket. We’d rather wait a little longer for a pair to be selected, then
     * process the incoming packets and send out ACKs, than try to process them
     * now, fail to send the ACKs, and incur a timeout in our pseudo-TCP state
     * machine. */
    if (component->selected_pair.local == NULL) {
      GOutputVector *vec = g_slice_new (GOutputVector);
      vec->buffer = compact_input_message (message, &vec->size);
      g_queue_push_tail (&component->queued_tcp_packets, vec);
      nice_debug ("%s: Queued %" G_GSSIZE_FORMAT " bytes for agent %p.",
          G_STRFUNC, vec->size, agent);

      return 0;
    } else {
      process_queued_tcp_packets (agent, stream, component);
    }

    /* Received data on a reliable connection. */

    nice_debug ("%s: notifying pseudo-TCP of packet, length %" G_GSIZE_FORMAT,
        G_STRFUNC, message->length);
    pseudo_tcp_socket_notify_message (component->tcp, message);

    adjust_tcp_clock (agent, stream, component);

    /* Success! Handled out-of-band. */
    retval = RECV_OOB;
    goto done;
  } else if (message->length > 0 && !component->tcp && agent->reliable) {
    /* Received data on a reliable connection which has no TCP component. */
    nice_debug ("Received data on a pseudo tcp FAILED component. Ignoring.");

    retval = RECV_OOB;
    goto done;
  }

done:
  /* Clear local modifications. */
  if (message->from == &from) {
    message->from = NULL;
  }

  return retval;
}

/* Print the composition of an array of messages. No-op if debugging is
 * disabled. */
static void
nice_debug_input_message_composition (const NiceInputMessage *messages,
    guint n_messages)
{
  guint i;

  if (!nice_debug_is_enabled ())
    return;

  for (i = 0; i < n_messages; i++) {
    const NiceInputMessage *message = &messages[i];
    guint j;

    nice_debug ("Message %p (from: %p, length: %" G_GSIZE_FORMAT ")", message,
        message->from, message->length);

    for (j = 0;
         (message->n_buffers >= 0 && j < (guint) message->n_buffers) ||
         (message->n_buffers < 0 && message->buffers[j].buffer != NULL);
         j++) {
      GInputVector *buffer = &message->buffers[j];

      nice_debug ("\tBuffer %p (length: %" G_GSIZE_FORMAT ")", buffer->buffer,
          buffer->size);
    }
  }
}

static guint8 *
compact_message (const NiceOutputMessage *message, gsize buffer_length)
{
  guint8 *buffer;
  gsize offset = 0;
  guint i;

  buffer = g_malloc (buffer_length);

  for (i = 0;
       (message->n_buffers >= 0 && i < (guint) message->n_buffers) ||
       (message->n_buffers < 0 && message->buffers[i].buffer != NULL);
       i++) {
    gsize len = MIN (buffer_length - offset, message->buffers[i].size);
    memcpy (buffer + offset, message->buffers[i].buffer, len);
    offset += len;
  }

  return buffer;
}

/* Concatenate all the buffers in the given @recv_message into a single, newly
 * allocated, monolithic buffer which is returned. The length of the new buffer
 * is returned in @buffer_length, and should be equal to the length field of
 * @recv_message.
 *
 * The return value must be freed with g_free(). */
guint8 *
compact_input_message (const NiceInputMessage *message, gsize *buffer_length)
{
  nice_debug ("%s: **WARNING: SLOW PATH**", G_STRFUNC);
  nice_debug_input_message_composition (message, 1);

  /* This works as long as NiceInputMessage is a subset of eNiceOutputMessage */

  *buffer_length = message->length;

  return compact_message ((NiceOutputMessage *) message, *buffer_length);
}

/* Returns the number of bytes copied. Silently drops any data from @buffer
 * which doesn’t fit in @message. */
gsize
memcpy_buffer_to_input_message (NiceInputMessage *message,
    const guint8 *buffer, gsize buffer_length)
{
  guint i;

  nice_debug ("%s: **WARNING: SLOW PATH**", G_STRFUNC);

  message->length = 0;

  for (i = 0;
       buffer_length > 0 &&
       ((message->n_buffers >= 0 && i < (guint) message->n_buffers) ||
        (message->n_buffers < 0 && message->buffers[i].buffer != NULL));
       i++) {
    gsize len;

    len = MIN (message->buffers[i].size, buffer_length);
    memcpy (message->buffers[i].buffer, buffer, len);

    buffer += len;
    buffer_length -= len;

    message->buffers[i].size = len;
    message->length += len;
  }

  nice_debug_input_message_composition (message, 1);

  if (buffer_length > 0) {
    g_warning ("Dropped %" G_GSIZE_FORMAT " bytes of data from the end of "
        "buffer %p (length: %" G_GSIZE_FORMAT ") due to not fitting in "
        "message %p", buffer_length, buffer - message->length,
        message->length + buffer_length, message);
  }

  return message->length;
}

/* Concatenate all the buffers in the given @message into a single, newly
 * allocated, monolithic buffer which is returned. The length of the new buffer
 * is returned in @buffer_length, and should be equal to the length field of
 * @recv_message.
 *
 * The return value must be freed with g_free(). */
guint8 *
compact_output_message (const NiceOutputMessage *message, gsize *buffer_length)
{
  nice_debug ("%s: **WARNING: SLOW PATH**", G_STRFUNC);

  *buffer_length = output_message_get_size (message);

  return compact_message (message, *buffer_length);
}

gsize
output_message_get_size (const NiceOutputMessage *message)
{
  guint i;
  gsize message_len = 0;

  /* Find the total size of the message */
  for (i = 0;
       (message->n_buffers >= 0 && i < (guint) message->n_buffers) ||
           (message->n_buffers < 0 && message->buffers[i].buffer != NULL);
       i++)
    message_len += message->buffers[i].size;

  return message_len;
}

static gsize
input_message_get_size (const NiceInputMessage *message)
{
  guint i;
  gsize message_len = 0;

  /* Find the total size of the message */
  for (i = 0;
       (message->n_buffers >= 0 && i < (guint) message->n_buffers) ||
           (message->n_buffers < 0 && message->buffers[i].buffer != NULL);
       i++)
    message_len += message->buffers[i].size;

  return message_len;
}

/*
 * nice_input_message_iter_reset:
 * @iter: a #NiceInputMessageIter
 *
 * Reset the given @iter to point to the beginning of the array of messages.
 * This may be used both to initialise it and to reset it after use.
 *
 * Since: 0.1.5
 */
void
nice_input_message_iter_reset (NiceInputMessageIter *iter)
{
  iter->message = 0;
  iter->buffer = 0;
  iter->offset = 0;
}

/*
 * nice_input_message_iter_is_at_end:
 * @iter: a #NiceInputMessageIter
 * @messages: (array length=n_messages): an array of #NiceInputMessages
 * @n_messages: number of entries in @messages
 *
 * Determine whether @iter points to the end of the given @messages array. If it
 * does, the array is full: every buffer in every message is full of valid
 * bytes.
 *
 * Returns: %TRUE if the messages’ buffers are full, %FALSE otherwise
 *
 * Since: 0.1.5
 */
gboolean
nice_input_message_iter_is_at_end (NiceInputMessageIter *iter,
    NiceInputMessage *messages, guint n_messages)
{
  return (iter->message == n_messages &&
      iter->buffer == 0 && iter->offset == 0);
}

/*
 * nice_input_message_iter_get_n_valid_messages:
 * @iter: a #NiceInputMessageIter
 *
 * Calculate the number of valid messages in the messages array. A valid message
 * is one which contains at least one valid byte of data in its buffers.
 *
 * Returns: number of valid messages (may be zero)
 *
 * Since: 0.1.5
 */
guint
nice_input_message_iter_get_n_valid_messages (NiceInputMessageIter *iter)
{
  if (iter->buffer == 0 && iter->offset == 0)
    return iter->message;
  else
    return iter->message + 1;
}

/**
 * nice_input_message_iter_compare:
 * @a: a #NiceInputMessageIter
 * @b: another #NiceInputMessageIter
 *
 * Compare two #NiceInputMessageIters for equality, returning %TRUE if they
 * point to the same place in the receive message array.
 *
 * Returns: %TRUE if the iters match, %FALSE otherwise
 *
 * Since: 0.1.5
 */
gboolean
nice_input_message_iter_compare (const NiceInputMessageIter *a,
    const NiceInputMessageIter *b)
{
  return (a->message == b->message && a->buffer == b->buffer && a->offset == b->offset);
}

/* Will fill up @messages from the first free byte onwards (as determined using
 * @iter). This may be used in reliable or non-reliable mode; in non-reliable
 * mode it will always increment the message index after each buffer is
 * consumed.
 *
 * Updates @iter in place. No errors can occur.
 *
 * Returns the number of valid messages in @messages on success (which may be
 * zero if reading into the first buffer of the message would have blocked).
 *
 * Must be called with the io_mutex held. */
static gint
pending_io_messages_recv_messages (Component *component, gboolean reliable,
    NiceInputMessage *messages, guint n_messages, NiceInputMessageIter *iter)
{
  gsize len;
  IOCallbackData *data;
  NiceInputMessage *message = &messages[iter->message];

  g_assert (component->io_callback_id == 0);

  data = g_queue_peek_head (&component->pending_io_messages);
  if (data == NULL)
    goto done;

  if (iter->buffer == 0 && iter->offset == 0) {
    message->length = 0;
  }

  for (;
       (message->n_buffers >= 0 && iter->buffer < (guint) message->n_buffers) ||
       (message->n_buffers < 0 && message->buffers[iter->buffer].buffer != NULL);
       iter->buffer++) {
    GInputVector *buffer = &message->buffers[iter->buffer];

    do {
      len = MIN (data->buf_len - data->offset, buffer->size - iter->offset);
      memcpy ((guint8 *) buffer->buffer + iter->offset,
          data->buf + data->offset, len);

      nice_debug ("%s: Unbuffered %" G_GSIZE_FORMAT " bytes into "
          "buffer %p (offset %" G_GSIZE_FORMAT ", length %" G_GSIZE_FORMAT
          ").", G_STRFUNC, len, buffer->buffer, iter->offset, buffer->size);

      message->length += len;
      iter->offset += len;
      data->offset += len;
    } while (iter->offset < buffer->size);

    iter->offset = 0;
  }

  /* Only if we managed to consume the whole buffer should it be popped off the
   * queue; otherwise we’ll have another go at it later. */
  if (data->offset == data->buf_len) {
    g_queue_pop_head (&component->pending_io_messages);
    io_callback_data_free (data);

    /* If we’ve consumed an entire message from pending_io_messages, and
     * are in non-reliable mode, move on to the next message in
     * @messages. */
    if (!reliable) {
      iter->offset = 0;
      iter->buffer = 0;
      iter->message++;
    }
  }

done:
  return nice_input_message_iter_get_n_valid_messages (iter);
}

static gboolean
nice_agent_recv_cancelled_cb (GCancellable *cancellable, gpointer user_data)
{
  GError **error = user_data;
  return !g_cancellable_set_error_if_cancelled (cancellable, error);
}

static gint
nice_agent_recv_messages_blocking_or_nonblocking (NiceAgent *agent,
  guint stream_id, guint component_id, gboolean blocking,
  NiceInputMessage *messages, guint n_messages,
  GCancellable *cancellable, GError **error)
{
  GMainContext *context;
  Stream *stream;
  Component *component;
  gint n_valid_messages = -1;
  GSource *cancellable_source = NULL;
  gboolean received_enough = FALSE, error_reported = FALSE;
  gboolean all_sockets_would_block = FALSE;
  GError *child_error = NULL;
  NiceInputMessage *messages_orig = NULL;
  guint i;

  g_return_val_if_fail (NICE_IS_AGENT (agent), -1);
  g_return_val_if_fail (stream_id >= 1, -1);
  g_return_val_if_fail (component_id >= 1, -1);
  g_return_val_if_fail (n_messages == 0 || messages != NULL, -1);
  g_return_val_if_fail (n_messages <= G_MAXINT, -1);
  g_return_val_if_fail (
      cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (n_messages == 0)
    return 0;

  if (n_messages > G_MAXINT) {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "The number of messages can't exceed G_MAXINT: %d", G_MAXINT);
    return -1;
  }

  /* Receive buffer size must be at least 1280 for STUN */
  if (!agent->reliable) {
    for (i = 0; i < n_messages; i++) {
      if (input_message_get_size (&messages[i]) < 1280) {
        GInputVector *vec;

        if (messages_orig == NULL)
          messages_orig = g_memdup (messages,
              sizeof (NiceInputMessage) * n_messages);
        vec = g_slice_new (GInputVector);
        vec->buffer = g_slice_alloc (1280);
        vec->size = 1280;
        messages[i].buffers = vec;
        messages[i].n_buffers = 1;
      }
    }
  }

  agent_lock ();

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component)) {
    g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE,
                 "Invalid stream/component.");
    goto done;
  }

  nice_debug ("%s: %p: (%s):", G_STRFUNC, agent,
      blocking ? "blocking" : "non-blocking");
  nice_debug_input_message_composition (messages, n_messages);

  /* Disallow re-entrant reads. */
  g_assert (component->n_recv_messages == 0 &&
      component->recv_messages == NULL);

  /* Set the component’s receive buffer. */
  context = component_dup_io_context (component);
  component_set_io_callback (component, NULL, NULL, messages, n_messages,
      &child_error);

  /* Add the cancellable as a source. */
  if (cancellable != NULL) {
    cancellable_source = g_cancellable_source_new (cancellable);
    g_source_set_callback (cancellable_source,
        (GSourceFunc) nice_agent_recv_cancelled_cb, &child_error, NULL);
    g_source_attach (cancellable_source, context);
  }

  /* Is there already pending data left over from having an I/O callback
   * attached and switching to using nice_agent_recv()? This is a horrifically
   * specific use case which I hope nobody ever tries. And yet, it still must be
   * supported. */
  g_mutex_lock (&component->io_mutex);

  while (!received_enough &&
         !g_queue_is_empty (&component->pending_io_messages)) {
    pending_io_messages_recv_messages (component, agent->reliable,
        component->recv_messages, component->n_recv_messages,
        &component->recv_messages_iter);

    nice_debug ("%s: %p: Received %d valid messages from pending I/O buffer.",
        G_STRFUNC, agent,
        nice_input_message_iter_get_n_valid_messages (
            &component->recv_messages_iter));

    received_enough =
        nice_input_message_iter_is_at_end (&component->recv_messages_iter,
            component->recv_messages, component->n_recv_messages);
  }

  g_mutex_unlock (&component->io_mutex);

  /* For a reliable stream, grab any data from the pseudo-TCP input buffer
   * before trying the sockets. */
  if (agent->reliable && component->tcp != NULL &&
      pseudo_tcp_socket_get_available_bytes (component->tcp) > 0) {
    pseudo_tcp_socket_recv_messages (component->tcp,
        component->recv_messages, component->n_recv_messages,
        &component->recv_messages_iter, &child_error);
    adjust_tcp_clock (agent, stream, component);

    nice_debug ("%s: %p: Received %d valid messages from pseudo-TCP read "
        "buffer.", G_STRFUNC, agent,
        nice_input_message_iter_get_n_valid_messages (
            &component->recv_messages_iter));

    received_enough =
        nice_input_message_iter_is_at_end (&component->recv_messages_iter,
            component->recv_messages, component->n_recv_messages);
    error_reported = (child_error != NULL);
  }

  /* Each iteration of the main context will either receive some data, a
   * cancellation error or a socket error. In non-reliable mode, the iter’s
   * @message counter will be incremented after each read.
   *
   * In blocking, reliable mode, iterate the loop enough to fill exactly
   * @n_messages messages. In blocking, non-reliable mode, iterate the loop to
   * receive @n_messages messages (which may not fill all the buffers). In
   * non-blocking mode, stop iterating the loop if all sockets would block (i.e.
   * if no data was received for an iteration).
   */
  while (!received_enough && !error_reported && !all_sockets_would_block) {
    NiceInputMessageIter prev_recv_messages_iter;

    memcpy (&prev_recv_messages_iter, &component->recv_messages_iter,
        sizeof (NiceInputMessageIter));


    agent_unlock_and_emit (agent);
    g_main_context_iteration (context, blocking);
    agent_lock ();

    if (!agent_find_component (agent, stream_id, component_id,
            &stream, &component)) {
      g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE,
          "Component removed during call.");
      goto done;
    }

    received_enough =
        nice_input_message_iter_is_at_end (&component->recv_messages_iter,
            component->recv_messages, component->n_recv_messages);
    error_reported = (child_error != NULL);
    all_sockets_would_block = (!blocking &&
        nice_input_message_iter_compare (&prev_recv_messages_iter,
            &component->recv_messages_iter));
  }

  n_valid_messages =
      nice_input_message_iter_get_n_valid_messages (
          &component->recv_messages_iter);  /* grab before resetting the iter */

  /* Tidy up. */
  if (cancellable_source != NULL) {
    g_source_destroy (cancellable_source);
    g_source_unref (cancellable_source);
  }

  component_set_io_callback (component, NULL, NULL, NULL, 0, NULL);
  g_main_context_unref (context);

  /* Handle errors and cancellations. */
  if (error_reported) {
    n_valid_messages = -1;
  } else if (n_valid_messages == 0 && all_sockets_would_block) {
    g_set_error_literal (&child_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
        g_strerror (EAGAIN));
    n_valid_messages = -1;
  }

  nice_debug ("%s: %p: n_valid_messages: %d, n_messages: %u", G_STRFUNC, agent,
      n_valid_messages, n_messages);

done:
  g_assert ((child_error != NULL) == (n_valid_messages == -1));
  g_assert (n_valid_messages < 0 || (guint) n_valid_messages <= n_messages);

  if (child_error != NULL)
    g_propagate_error (error, child_error);

  agent_unlock_and_emit (agent);

  if (messages_orig) {
    for (i = 0; i < n_messages; i++) {
      if (messages[i].buffers != messages_orig[i].buffers) {
        g_assert_cmpint (messages[i].n_buffers, ==, 1);

        memcpy_buffer_to_input_message (&messages_orig[i],
            messages[i].buffers[0].buffer, messages[i].length);

        g_slice_free1 (1280, messages[i].buffers[0].buffer);
        g_slice_free (GInputVector, messages[i].buffers);

        messages[i].buffers = messages_orig[i].buffers;
        messages[i].n_buffers = messages_orig[i].n_buffers;
        messages[i].length = messages_orig[i].length;
      }
    }
    g_free (messages_orig);
  }

  return n_valid_messages;
}

NICEAPI_EXPORT gint
nice_agent_recv_messages (NiceAgent *agent, guint stream_id, guint component_id,
  NiceInputMessage *messages, guint n_messages, GCancellable *cancellable,
  GError **error)
{
  return nice_agent_recv_messages_blocking_or_nonblocking (agent, stream_id,
      component_id, TRUE, messages, n_messages, cancellable, error);
}

NICEAPI_EXPORT gssize
nice_agent_recv (NiceAgent *agent, guint stream_id, guint component_id,
  guint8 *buf, gsize buf_len, GCancellable *cancellable, GError **error)
{
  gint n_valid_messages;
  GInputVector local_bufs = { buf, buf_len };
  NiceInputMessage local_messages = { &local_bufs, 1, NULL, 0 };

  if (buf_len > G_MAXSSIZE) {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "The buffer length can't exceed G_MAXSSIZE: %" G_GSSIZE_FORMAT,
        G_MAXSSIZE);
    return -1;
  }

  n_valid_messages = nice_agent_recv_messages (agent, stream_id, component_id,
      &local_messages, 1, cancellable, error);

  if (n_valid_messages <= 0)
    return n_valid_messages;

  return local_messages.length;
}

NICEAPI_EXPORT gint
nice_agent_recv_messages_nonblocking (NiceAgent *agent, guint stream_id,
    guint component_id, NiceInputMessage *messages, guint n_messages,
    GCancellable *cancellable, GError **error)
{
  return nice_agent_recv_messages_blocking_or_nonblocking (agent, stream_id,
      component_id, FALSE, messages, n_messages, cancellable, error);
}

NICEAPI_EXPORT gssize
nice_agent_recv_nonblocking (NiceAgent *agent, guint stream_id,
    guint component_id, guint8 *buf, gsize buf_len, GCancellable *cancellable,
    GError **error)
{
  gint n_valid_messages;
  GInputVector local_bufs = { buf, buf_len };
  NiceInputMessage local_messages = { &local_bufs, 1, NULL, 0 };

  if (buf_len > G_MAXSSIZE) {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "The buffer length can't exceed G_MAXSSIZE: %" G_GSSIZE_FORMAT,
        G_MAXSSIZE);
    return -1;
  }

  n_valid_messages = nice_agent_recv_messages_nonblocking (agent, stream_id,
      component_id, &local_messages, 1, cancellable, error);

  if (n_valid_messages <= 0)
    return n_valid_messages;

  return local_messages.length;
}

/* nice_agent_send_messages_nonblocking_internal:
 *
 * Returns: number of bytes sent if allow_partial is %TRUE, the number
 * of messages otherwise.
 */

static gint
nice_agent_send_messages_nonblocking_internal (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const NiceOutputMessage *messages,
  guint n_messages,
  gboolean allow_partial,
  GError **error)
{
  Stream *stream;
  Component *component;
  gint n_sent = -1; /* is in bytes if allow_partial is TRUE,
                       otherwise in messages */
  GError *child_error = NULL;

  g_assert (n_messages == 1 || !allow_partial);

  agent_lock ();

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component)) {
    g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE,
                 "Invalid stream/component.");
    goto done;
  }

  /* FIXME: Cancellation isn’t yet supported, but it doesn’t matter because
   * we only deal with non-blocking writes. */

  if (component->tcp != NULL) {
    /* Send on the pseudo-TCP socket. */
    n_sent = pseudo_tcp_socket_send_messages (component->tcp, messages,
        n_messages, allow_partial, &child_error);
    adjust_tcp_clock (agent, stream, component);

    if (!pseudo_tcp_socket_can_send (component->tcp))
      g_cancellable_reset (component->tcp_writable_cancellable);
    if (n_sent < 0 && !g_error_matches (child_error, G_IO_ERROR,
            G_IO_ERROR_WOULD_BLOCK)) {
      /* Signal errors */
      priv_pseudo_tcp_error (agent, stream, component);
    }
  } else if (agent->reliable) {
    g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "Error writing data to failed pseudo-TCP socket.");
  } else if (component->selected_pair.local != NULL) {
    NiceSocket *sock;
    NiceAddress *addr;

    if (nice_debug_is_enabled ()) {
      gchar tmpbuf[INET6_ADDRSTRLEN];
      nice_address_to_string (&component->selected_pair.remote->addr, tmpbuf);

      nice_debug ("Agent %p : s%d:%d: sending %u messages to "
          "[%s]:%d", agent, stream_id, component_id, n_messages, tmpbuf,
          nice_address_get_port (&component->selected_pair.remote->addr));
    }

    sock = component->selected_pair.local->sockptr;
    addr = &component->selected_pair.remote->addr;

    n_sent = nice_socket_send_messages (sock, addr, messages, n_messages);

    if (n_sent < 0) {
      g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "Error writing data to socket.");
    } else if (allow_partial) {
      g_assert (n_messages == 1);
      n_sent = output_message_get_size (messages);
    }
  } else {
    /* Socket isn’t properly open yet. */
    n_sent = 0;  /* EWOULDBLOCK */
  }

  /* Handle errors and cancellations. */
  if (n_sent == 0) {
    g_set_error_literal (&child_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
        g_strerror (EAGAIN));
    n_sent = -1;
  }

  nice_debug ("%s: n_sent: %d, n_messages: %u", G_STRFUNC,
      n_sent, n_messages);

done:
  g_assert ((child_error != NULL) == (n_sent == -1));
  g_assert (n_sent != 0);
  g_assert (n_sent < 0 ||
      (!allow_partial && (guint) n_sent <= n_messages) ||
      (allow_partial && n_messages == 1 &&
          (gsize) n_sent <= output_message_get_size (&messages[0])));

  if (child_error != NULL)
    g_propagate_error (error, child_error);

  agent_unlock_and_emit (agent);

  return n_sent;
}

NICEAPI_EXPORT gint
nice_agent_send_messages_nonblocking (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const NiceOutputMessage *messages,
  guint n_messages,
  GCancellable *cancellable,
  GError **error)
{
  g_return_val_if_fail (NICE_IS_AGENT (agent), -1);
  g_return_val_if_fail (stream_id >= 1, -1);
  g_return_val_if_fail (component_id >= 1, -1);
  g_return_val_if_fail (n_messages == 0 || messages != NULL, -1);
  g_return_val_if_fail (
      cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return -1;

  return nice_agent_send_messages_nonblocking_internal (agent, stream_id,
      component_id, messages, n_messages, FALSE, error);
}

NICEAPI_EXPORT gint
nice_agent_send (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  const gchar *buf)
{
  GOutputVector local_buf = { buf, len };
  NiceOutputMessage local_message = { &local_buf, 1 };
  gint n_sent_bytes;

  g_return_val_if_fail (NICE_IS_AGENT (agent), -1);
  g_return_val_if_fail (stream_id >= 1, -1);
  g_return_val_if_fail (component_id >= 1, -1);
  g_return_val_if_fail (buf != NULL, -1);

  n_sent_bytes = nice_agent_send_messages_nonblocking_internal (agent,
      stream_id, component_id, &local_message, 1, TRUE, NULL);

  return n_sent_bytes;
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

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    goto done;
  }

  for (item = component->local_candidates; item; item = item->next)
    ret = g_slist_append (ret, nice_candidate_copy (item->data));

 done:
  agent_unlock_and_emit (agent);
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

  agent_lock();
  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    {
      goto done;
    }

  for (item = component->remote_candidates; item; item = item->next)
    ret = g_slist_append (ret, nice_candidate_copy (item->data));

 done:
  agent_unlock_and_emit (agent);
  return ret;
}


gboolean
nice_agent_restart (
  NiceAgent *agent)
{
  GSList *i;
  gboolean res = TRUE;

  agent_lock();

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

  agent_unlock_and_emit (agent);
  return res;
}


static void
nice_agent_dispose (GObject *object)
{
  GSList *i;
  QueuedSignal *sig;
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

  while ((sig = g_queue_pop_head (&agent->pending_signals))) {
    free_queued_signal (sig);
  }

  g_free (agent->stun_server_ip);
  agent->stun_server_ip = NULL;

  g_free (agent->proxy_ip);
  agent->proxy_ip = NULL;
  g_free (agent->proxy_username);
  agent->proxy_username = NULL;
  g_free (agent->proxy_password);
  agent->proxy_password = NULL;

  nice_rng_free (agent->rng);
  agent->rng = NULL;

  priv_free_upnp (agent);

  g_free (agent->software_attribute);
  agent->software_attribute = NULL;

  if (agent->main_context != NULL)
    g_main_context_unref (agent->main_context);
  agent->main_context = NULL;

  if (G_OBJECT_CLASS (nice_agent_parent_class)->dispose)
    G_OBJECT_CLASS (nice_agent_parent_class)->dispose (object);

}

gboolean
component_io_cb (GSocket *socket, GIOCondition condition, gpointer user_data)
{
  SocketSource *socket_source = user_data;
  Component *component;
  NiceAgent *agent;
  Stream *stream;
  gboolean has_io_callback;
  gboolean remove_source = FALSE;

  agent_lock ();

  if (g_source_is_destroyed (g_main_current_source ())) {
    /* Silently return FALSE. */
    nice_debug ("%s: source %p destroyed", G_STRFUNC, g_main_current_source ());

    agent_unlock ();
    return G_SOURCE_REMOVE;
  }

  component = socket_source->component;
  agent = component->agent;
  stream = component->stream;

  g_object_ref (agent);

  has_io_callback = component_has_io_callback (component);

  /* Choose which receive buffer to use. If we’re reading for
   * nice_agent_attach_recv(), use a local static buffer. If we’re reading for
   * nice_agent_recv_messages(), use the buffer provided by the client.
   *
   * has_io_callback cannot change throughout this function, as we operate
   * entirely with the agent lock held, and component_set_io_callback() would
   * need to take the agent lock to change the Component’s io_callback. */
  g_assert (!has_io_callback || component->recv_messages == NULL);

  if (agent->reliable) {
#define TCP_HEADER_SIZE 24 /* bytes */
    guint8 local_header_buf[TCP_HEADER_SIZE];
    /* FIXME: Currently, the critical path for reliable packet delivery has two
     * memcpy()s: one into the pseudo-TCP receive buffer, and one out of it.
     * This could moderately easily be reduced to one memcpy() in the common
     * case of in-order packet delivery, by replacing local_body_buf with a
     * pointer into the pseudo-TCP receive buffer. If it turns out the packet
     * is out-of-order (which we can only know after parsing its header), the
     * data will need to be moved in the buffer. If the packet *is* in order,
     * however, the only memcpy() then needed is from the pseudo-TCP receive
     * buffer to the client’s message buffers.
     *
     * In fact, in the case of a reliable agent with I/O callbacks, zero
     * memcpy()s can be achieved (for in-order packet delivery) by emittin the
     * I/O callback directly from the pseudo-TCP receive buffer. */
    guint8 local_body_buf[MAX_BUFFER_SIZE];
    GInputVector local_bufs[] = {
      { local_header_buf, sizeof (local_header_buf) },
      { local_body_buf, sizeof (local_body_buf) },
    };
    NiceInputMessage local_message = {
      local_bufs, G_N_ELEMENTS (local_bufs), NULL, 0
    };
    RecvStatus retval = 0;

    if (component->tcp == NULL) {
      nice_debug ("Agent %p: not handling incoming packet for s%d:%d "
          "because pseudo-TCP socket does not exist in reliable mode.", agent,
          stream->id, component->id);
      remove_source = TRUE;
      goto done;
    }

    while (has_io_callback ||
           (component->recv_messages != NULL &&
            !nice_input_message_iter_is_at_end (&component->recv_messages_iter,
                component->recv_messages, component->n_recv_messages))) {
      /* Receive a single message. This will receive it into the given
       * @local_bufs then, for pseudo-TCP, emit I/O callbacks or copy it into
       * component->recv_messages in pseudo_tcp_socket_readable(). STUN packets
       * will be parsed in-place. */
      retval = agent_recv_message_unlocked (agent, stream, component,
          socket_source->socket, &local_message);

      nice_debug ("%s: %p: received %d valid messages with %" G_GSSIZE_FORMAT
           " bytes", G_STRFUNC, agent, retval, local_message.length);

      /* Don’t expect any valid messages to escape pseudo_tcp_socket_readable()
       * when in reliable mode. */
      g_assert_cmpint (retval, !=, RECV_SUCCESS);

      if (retval == RECV_WOULD_BLOCK) {
        /* EWOULDBLOCK. */
        break;
      } else if (retval == RECV_ERROR) {
        /* Other error. */
        nice_debug ("%s: error receiving message", G_STRFUNC);
        remove_source = TRUE;
        break;
      }

      has_io_callback = component_has_io_callback (component);
    }
  } else if (!agent->reliable && has_io_callback) {
    while (has_io_callback) {
      guint8 local_buf[MAX_BUFFER_SIZE];
      GInputVector local_bufs = { local_buf, sizeof (local_buf) };
      NiceInputMessage local_message = { &local_bufs, 1, NULL, 0 };
      RecvStatus retval;

      /* Receive a single message. */
      retval = agent_recv_message_unlocked (agent, stream, component,
          socket_source->socket, &local_message);

      nice_debug ("%s: %p: received %d valid messages with %" G_GSSIZE_FORMAT
           " bytes", G_STRFUNC, agent, retval, local_message.length);

      if (retval == RECV_WOULD_BLOCK) {
        /* EWOULDBLOCK. */
        break;
      } else if (retval == RECV_ERROR) {
        /* Other error. */
        nice_debug ("%s: error receiving message", G_STRFUNC);
        remove_source = TRUE;
        break;
      }

      if (retval == RECV_SUCCESS && local_message.length > 0)
        component_emit_io_callback (component, local_buf, local_message.length);

      has_io_callback = component_has_io_callback (component);
    }
  } else if (!agent->reliable && component->recv_messages != NULL) {
    RecvStatus retval;

    /* Don’t want to trample over partially-valid buffers. */
    g_assert (component->recv_messages_iter.buffer == 0);
    g_assert (component->recv_messages_iter.offset == 0);

    while (!nice_input_message_iter_is_at_end (&component->recv_messages_iter,
        component->recv_messages, component->n_recv_messages)) {
      /* Receive a single message. This will receive it into the given
       * user-provided #NiceInputMessage, which it’s the user’s responsibility
       * to ensure is big enough to avoid data loss (since we’re in non-reliable
       * mode). Iterate to receive as many messages as possible.
       *
       * STUN packets will be parsed in-place. */
      retval = agent_recv_message_unlocked (agent, stream, component,
          socket_source->socket,
          &component->recv_messages[component->recv_messages_iter.message]);

      nice_debug ("%s: %p: received %d valid messages", G_STRFUNC, agent,
          retval);

      if (retval == RECV_SUCCESS) {
        /* Successfully received a single message. */
        component->recv_messages_iter.message++;
      } else if (retval == RECV_WOULD_BLOCK) {
        /* EWOULDBLOCK. */
        break;
      } else if (retval == RECV_ERROR) {
        /* Other error. */
        remove_source = TRUE;
        break;
      } /* else if (retval == RECV_OOB) { ignore me and continue; } */
    }
  }

done:
  /* If we’re in the middle of a read, don’t emit any signals, or we could cause
   * re-entrancy by (e.g.) emitting component-state-changed and having the
   * client perform a read. */
  if (component->n_recv_messages == 0 && component->recv_messages == NULL) {
    agent_unlock_and_emit (agent);
  } else {
    agent_unlock ();
  }

  g_object_unref (agent);

  return !remove_source;
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

  agent_lock();

  /* attach candidates */

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    g_warning ("Could not find component %u in stream %u", component_id,
        stream_id);
    goto done;
  }

  if (ctx == NULL)
    ctx = g_main_context_default ();

  /* Set the component’s I/O context. */
  component_set_io_context (component, ctx);
  component_set_io_callback (component, func, data, NULL, 0, NULL);
  ret = TRUE;

  if (func) {
    /* If we got detached, maybe our readable callback didn't finish reading
     * all available data in the pseudotcp, so we need to make sure we free
     * our recv window, so the readable callback can be triggered again on the
     * next incoming data.
     * but only do this if we know we're already readable, otherwise we might
     * trigger an error in the initial, pre-connection attach. */
    if (component->tcp && component->tcp_readable)
      pseudo_tcp_socket_readable (component->tcp, component);
  }

 done:
  agent_unlock_and_emit (agent);
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

  agent_lock();

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  if (!component_find_pair (component, agent, lfoundation, rfoundation, &pair)){
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream);

  if (agent->reliable && component->tcp == NULL) {
    nice_debug ("Agent %p: not setting selected pair for s%d:%d because "
        "pseudo tcp socket does not exist in reliable mode", agent,
        stream->id, component->id);
    goto done;
  }

  /* step: change component state */
  agent_signal_component_state_change (agent, stream_id, component_id, NICE_COMPONENT_STATE_READY);

  /* step: set the selected pair */
  component_update_selected_pair (component, &pair);
  agent_signal_new_selected_pair (agent, stream_id, component_id, lfoundation, rfoundation);

  ret = TRUE;

 done:
  agent_unlock_and_emit (agent);
  return ret;
}

NICEAPI_EXPORT gboolean
nice_agent_get_selected_pair (NiceAgent *agent, guint stream_id,
    guint component_id, NiceCandidate **local, NiceCandidate **remote)
{
  Component *component;
  Stream *stream;
  gboolean ret = FALSE;

  agent_lock();

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    goto done;

  if (component->selected_pair.local && component->selected_pair.remote) {
    *local = component->selected_pair.local;
    *remote = component->selected_pair.remote;
    ret = TRUE;
  }

 done:
  agent_unlock_and_emit (agent);

  return ret;
}

NICEAPI_EXPORT GSocket *
nice_agent_get_selected_socket (NiceAgent *agent, guint stream_id,
    guint component_id)
{
  Component *component;
  Stream *stream;
  NiceSocket *nice_socket;
  GSocket *g_socket = NULL;

  agent_lock();

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    goto done;

  if (!component->selected_pair.local || !component->selected_pair.remote)
    goto done;

  if (component->selected_pair.local->type == NICE_CANDIDATE_TYPE_RELAYED)
    goto done;

  nice_socket = (NiceSocket *)component->selected_pair.local->sockptr;
  if (nice_socket->fileno)
    g_socket = g_object_ref (nice_socket->fileno);

 done:
  agent_unlock_and_emit (agent);

  return g_socket;
}

GSource* agent_timeout_add_with_context (NiceAgent *agent, guint interval,
    GSourceFunc function, gpointer data)
{
  GSource *source;

  g_return_val_if_fail (function != NULL, NULL);

  source = g_timeout_source_new (interval);

  g_source_set_callback (source, function, data, NULL);
  g_source_attach (source, agent->main_context);

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

  agent_lock();

  /* step: check if the component exists*/
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream);


  if (agent->reliable && component->tcp == NULL) {
    nice_debug ("Agent %p: not setting selected remote candidate s%d:%d because "
        "pseudo tcp socket does not exist in reliable mode", agent,
        stream->id, component->id);
    goto done;
  }

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
  agent_unlock_and_emit (agent);
  return ret;
}

void
_priv_set_socket_tos (NiceAgent *agent, NiceSocket *sock, gint tos)
{
  if (setsockopt (g_socket_get_fd (sock->fileno), IPPROTO_IP,
          IP_TOS, (const char *) &tos, sizeof (tos)) < 0) {
    nice_debug ("Agent %p: Could not set socket ToS: %s", agent,
        g_strerror (errno));
  }
#ifdef IPV6_TCLASS
  if (setsockopt (g_socket_get_fd (sock->fileno), IPPROTO_IPV6,
          IPV6_TCLASS, (const char *) &tos, sizeof (tos)) < 0) {
    nice_debug ("Agent %p: Could not set IPV6 socket ToS: %s", agent,
        g_strerror (errno));
  }
#endif
}


NICEAPI_EXPORT void
nice_agent_set_stream_tos (NiceAgent *agent,
  guint stream_id, gint tos)
{
  GSList *i, *j;
  Stream *stream;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL)
    goto done;

  stream->tos = tos;
  for (i = stream->components; i; i = i->next) {
    Component *component = i->data;

    for (j = component->local_candidates; j; j = j->next) {
      NiceCandidate *local_candidate = j->data;

      _priv_set_socket_tos (agent, local_candidate->sockptr, tos);
    }
  }

 done:
  agent_unlock_and_emit (agent);
}

NICEAPI_EXPORT void
nice_agent_set_software (NiceAgent *agent, const gchar *software)
{
  agent_lock();

  g_free (agent->software_attribute);
  if (software)
    agent->software_attribute = g_strdup_printf ("%s/%s",
        software, PACKAGE_STRING);

  stun_agent_set_software (&agent->stun_agent, agent->software_attribute);

  agent_unlock_and_emit (agent);
}

NICEAPI_EXPORT gboolean
nice_agent_set_stream_name (NiceAgent *agent, guint stream_id,
    const gchar *name)
{
  Stream *stream_to_name = NULL;
  GSList *i;
  gboolean ret = FALSE;

  agent_lock();

  if (name != NULL) {
    for (i = agent->streams; i; i = i->next) {
      Stream *stream = i->data;

      if (stream->id != stream_id &&
          g_strcmp0 (stream->name, name) == 0)
        goto done;
      else if (stream->id == stream_id)
        stream_to_name = stream;
    }
  }

  if (stream_to_name == NULL)
    goto done;

  if (stream_to_name->name)
    g_free (stream_to_name->name);
  stream_to_name->name = g_strdup (name);
  ret = TRUE;

 done:
  agent_unlock_and_emit (agent);

  return ret;
}

NICEAPI_EXPORT const gchar *
nice_agent_get_stream_name (NiceAgent *agent, guint stream_id)
{
  Stream *stream;
  gchar *name = NULL;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL)
    goto done;

  name = stream->name;

 done:
  agent_unlock_and_emit (agent);
  return name;
}

static NiceCandidate *
_get_default_local_candidate_locked (NiceAgent *agent,
    Stream *stream,  Component *component)
{
  GSList *i;
  NiceCandidate *default_candidate = NULL;
  NiceCandidate *default_rtp_candidate = NULL;

  if (component->id != NICE_COMPONENT_TYPE_RTP) {
    Component *rtp_component;

    if (!agent_find_component (agent, stream->id, NICE_COMPONENT_TYPE_RTP,
            NULL, &rtp_component))
      goto done;

    default_rtp_candidate = _get_default_local_candidate_locked (agent, stream,
        rtp_component);
    if (default_rtp_candidate == NULL)
      goto done;
  }


  for (i = component->local_candidates; i; i = i->next) {
    NiceCandidate *local_candidate = i->data;

    /* Only check for ipv4 candidates */
    if (nice_address_ip_version (&local_candidate->addr) != 4)
      continue;
    if (component->id == NICE_COMPONENT_TYPE_RTP) {
      if (default_candidate == NULL ||
          local_candidate->priority < default_candidate->priority) {
        default_candidate = local_candidate;
      }
    } else if (strncmp (local_candidate->foundation,
            default_rtp_candidate->foundation,
            NICE_CANDIDATE_MAX_FOUNDATION) == 0) {
      default_candidate = local_candidate;
      break;
    }
  }

 done:
  return default_candidate;
}

NICEAPI_EXPORT NiceCandidate *
nice_agent_get_default_local_candidate (NiceAgent *agent,
    guint stream_id,  guint component_id)
{
  Stream *stream = NULL;
  Component *component = NULL;
  NiceCandidate *default_candidate = NULL;

  agent_lock ();

  /* step: check if the component exists*/
  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    goto done;

  default_candidate = _get_default_local_candidate_locked (agent, stream,
      component);
  if (default_candidate)
    default_candidate = nice_candidate_copy (default_candidate);

 done:
  agent_unlock_and_emit (agent);

  return default_candidate;
}

static const gchar *
_cand_type_to_sdp (NiceCandidateType type) {
  switch(type) {
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
      return "srflx";
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
      return "prflx";
    case NICE_CANDIDATE_TYPE_RELAYED:
      return "relay";
    case NICE_CANDIDATE_TYPE_HOST:
    default:
      return "host";
  }
}

static void
_generate_candidate_sdp (NiceAgent *agent,
    NiceCandidate *candidate, GString *sdp)
{
  gchar ip4[INET6_ADDRSTRLEN];

  nice_address_to_string (&candidate->addr, ip4);
  g_string_append_printf (sdp, "a=candidate:%.*s %d %s %d %s %d",
      NICE_CANDIDATE_MAX_FOUNDATION, candidate->foundation,
      candidate->component_id,
      candidate->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "UDP" : "???",
      candidate->priority, ip4, nice_address_get_port (&candidate->addr));
  g_string_append_printf (sdp, " typ %s", _cand_type_to_sdp (candidate->type));
  if (nice_address_is_valid (&candidate->base_addr) &&
      !nice_address_equal (&candidate->addr, &candidate->base_addr)) {
    nice_address_to_string (&candidate->base_addr, ip4);
    g_string_append_printf (sdp, " raddr %s rport %d", ip4,
        nice_address_get_port (&candidate->base_addr));
  }
}

static void
_generate_stream_sdp (NiceAgent *agent, Stream *stream,
    GString *sdp, gboolean include_non_ice)
{
  GSList *i, *j;

  if (include_non_ice) {
    NiceAddress rtp, rtcp;
    gchar ip4[INET6_ADDRSTRLEN];

    nice_address_init (&rtp);
    nice_address_set_ipv4 (&rtp, 0);
    nice_address_init (&rtcp);
    nice_address_set_ipv4 (&rtcp, 0);

    /* Find default candidates */
    for (i = stream->components; i; i = i->next) {
      Component *component = i->data;
      NiceCandidate *default_candidate;

      if (component->id == NICE_COMPONENT_TYPE_RTP) {
        default_candidate = _get_default_local_candidate_locked (agent, stream,
            component);
        if (default_candidate)
          rtp = default_candidate->addr;
      } else if (component->id == NICE_COMPONENT_TYPE_RTCP) {
        default_candidate = _get_default_local_candidate_locked (agent, stream,
            component);
        if (default_candidate)
          rtcp = default_candidate->addr;
      }
    }

    nice_address_to_string (&rtp, ip4);
    g_string_append_printf (sdp, "m=%s %d ICE/SDP\n",
        stream->name ? stream->name : "-", nice_address_get_port (&rtp));
    g_string_append_printf (sdp, "c=IN IP4 %s\n", ip4);
    if (nice_address_get_port (&rtcp) != 0)
      g_string_append_printf (sdp, "a=rtcp:%d\n",
          nice_address_get_port (&rtcp));
  }

  g_string_append_printf (sdp, "a=ice-ufrag:%s\n", stream->local_ufrag);
  g_string_append_printf (sdp, "a=ice-pwd:%s\n", stream->local_password);

  for (i = stream->components; i; i = i->next) {
    Component *component = i->data;

    for (j = component->local_candidates; j; j = j->next) {
      NiceCandidate *candidate = j->data;

      _generate_candidate_sdp (agent, candidate, sdp);
      g_string_append (sdp, "\n");
    }
  }
}

NICEAPI_EXPORT gchar *
nice_agent_generate_local_sdp (NiceAgent *agent)
{
  GString * sdp = g_string_new (NULL);
  GSList *i;

  agent_lock();

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;

    _generate_stream_sdp (agent, stream, sdp, TRUE);
  }

  agent_unlock_and_emit (agent);

  return g_string_free (sdp, FALSE);
}

NICEAPI_EXPORT gchar *
nice_agent_generate_local_stream_sdp (NiceAgent *agent, guint stream_id,
    gboolean include_non_ice)
{
  GString *sdp = NULL;
  gchar *ret = NULL;
  Stream *stream;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL)
    goto done;

  sdp = g_string_new (NULL);
  _generate_stream_sdp (agent, stream, sdp, include_non_ice);
  ret = g_string_free (sdp, FALSE);

 done:
  agent_unlock_and_emit (agent);

  return ret;
}

NICEAPI_EXPORT gchar *
nice_agent_generate_local_candidate_sdp (NiceAgent *agent,
    NiceCandidate *candidate)
{
  GString *sdp = NULL;

  g_return_val_if_fail(candidate, NULL);

  agent_lock();

  sdp = g_string_new (NULL);
  _generate_candidate_sdp (agent, candidate, sdp);

  agent_unlock_and_emit (agent);

  return g_string_free (sdp, FALSE);
}

NICEAPI_EXPORT gint
nice_agent_parse_remote_sdp (NiceAgent *agent, const gchar *sdp)
{
  Stream *current_stream = NULL;
  gchar **sdp_lines = NULL;
  GSList *l;
  gint i;
  gint ret = 0;

  agent_lock();

  for (l = agent->streams; l; l = l->next) {
    Stream *stream = l->data;

    if (stream->name == NULL) {
      ret = -1;
      goto done;
    }
  }

  sdp_lines = g_strsplit (sdp, "\n", 0);
  for (i = 0; sdp_lines && sdp_lines[i]; i++) {
    if (g_str_has_prefix (sdp_lines[i], "m=")) {
      gchar *name = g_strdup (sdp_lines[i] + 2);
      gchar *ptr = name;

      while (*ptr != ' ' && *ptr != '\0') ptr++;
      *ptr = 0;

      current_stream = NULL;
      for (l = agent->streams; l; l = l->next) {
        Stream *stream = l->data;

        if (g_strcmp0 (stream->name, name) == 0) {
          current_stream = stream;
          break;
        }
      }
      g_free (name);
    } else if (g_str_has_prefix (sdp_lines[i], "a=ice-ufrag:")) {
      if (current_stream == NULL) {
        ret = -1;
        goto done;
      }
      g_strlcpy (current_stream->remote_ufrag, sdp_lines[i] + 12,
          NICE_STREAM_MAX_UFRAG);
    } else if (g_str_has_prefix (sdp_lines[i], "a=ice-pwd:")) {
      if (current_stream == NULL) {
        ret = -1;
        goto done;
      }
      g_strlcpy (current_stream->remote_password, sdp_lines[i] + 10,
          NICE_STREAM_MAX_PWD);
    } else if (g_str_has_prefix (sdp_lines[i], "a=candidate:")) {
      NiceCandidate *candidate = NULL;
      Component *component = NULL;
      GSList *cands = NULL;
      gint added;

      if (current_stream == NULL) {
        ret = -1;
        goto done;
      }
      candidate = nice_agent_parse_remote_candidate_sdp (agent,
          current_stream->id, sdp_lines[i]);
      if (candidate == NULL) {
        ret = -1;
        goto done;
      }

      if (!agent_find_component (agent, candidate->stream_id,
              candidate->component_id, NULL, &component)) {
        nice_candidate_free (candidate);
        ret = -1;
        goto done;
      }
      cands = g_slist_prepend (cands, candidate);
      added = _set_remote_candidates_locked (agent, current_stream,
          component, cands);
      g_slist_free_full(cands, (GDestroyNotify)&nice_candidate_free);
      if (added > 0)
        ret++;
    }
  }

 done:
  if (sdp_lines)
    g_strfreev(sdp_lines);

  agent_unlock_and_emit (agent);

  return ret;
}

NICEAPI_EXPORT GSList *
nice_agent_parse_remote_stream_sdp (NiceAgent *agent, guint stream_id,
    const gchar *sdp, gchar **ufrag, gchar **pwd)
{
  Stream *stream = NULL;
  gchar **sdp_lines = NULL;
  GSList *candidates = NULL;
  gint i;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    goto done;
  }

  sdp_lines = g_strsplit (sdp, "\n", 0);
  for (i = 0; sdp_lines && sdp_lines[i]; i++) {
    if (ufrag && g_str_has_prefix (sdp_lines[i], "a=ice-ufrag:")) {
      *ufrag = g_strdup (sdp_lines[i] + 12);
    } else if (pwd && g_str_has_prefix (sdp_lines[i], "a=ice-pwd:")) {
      *pwd = g_strdup (sdp_lines[i] + 10);
    } else if (g_str_has_prefix (sdp_lines[i], "a=candidate:")) {
      NiceCandidate *candidate = NULL;

      candidate = nice_agent_parse_remote_candidate_sdp (agent, stream->id,
          sdp_lines[i]);
      if (candidate == NULL) {
        g_slist_free_full(candidates, (GDestroyNotify)&nice_candidate_free);
        candidates = NULL;
        break;
      }
      candidates = g_slist_prepend (candidates, candidate);
    }
  }

 done:
  if (sdp_lines)
    g_strfreev(sdp_lines);

  agent_unlock_and_emit (agent);

  return candidates;
}

NICEAPI_EXPORT NiceCandidate *
nice_agent_parse_remote_candidate_sdp (NiceAgent *agent, guint stream_id,
    const gchar *sdp)
{
  NiceCandidate *candidate = NULL;
  int ntype = -1;
  gchar **tokens = NULL;
  const gchar *foundation = NULL;
  guint component_id;
  const gchar *transport = NULL;
  guint32 priority;
  const gchar *addr = NULL;
  guint16 port;
  const gchar *type = NULL;
  const gchar *raddr = NULL;
  guint16 rport = 0;
  static const gchar *type_names[] = {"host", "srflx", "prflx", "relay"};
  guint i;

  if (!g_str_has_prefix (sdp, "a=candidate:"))
    goto done;

  tokens = g_strsplit (sdp + 12, " ", 0);
  for (i = 0; tokens && tokens[i]; i++) {
    switch (i) {
      case 0:
        foundation = tokens[i];
        break;
      case 1:
        component_id = (guint) g_ascii_strtoull (tokens[i], NULL, 10);
        break;
      case 2:
        transport = tokens[i];
        break;
      case 3:
        priority = (guint32) g_ascii_strtoull (tokens[i], NULL, 10);
        break;
      case 4:
        addr = tokens[i];
        break;
      case 5:
        port = (guint16) g_ascii_strtoull (tokens[i], NULL, 10);
        break;
      default:
        if (tokens[i + 1] == NULL)
          goto done;

        if (g_strcmp0 (tokens[i], "typ") == 0) {
          type = tokens[i + 1];
        } else if (g_strcmp0 (tokens[i], "raddr") == 0) {
          raddr = tokens[i + 1];
        } else if (g_strcmp0 (tokens[i], "rport") == 0) {
          rport = (guint16) g_ascii_strtoull (tokens[i + 1], NULL, 10);
        }
        i++;
        break;
    }
  }
  if (type == NULL)
    goto done;

  ntype = -1;
  for (i = 0; i < G_N_ELEMENTS (type_names); i++) {
    if (g_strcmp0 (type, type_names[i]) == 0) {
      ntype = i;
      break;
    }
  }
  if (ntype == -1)
    goto done;

  if (g_strcmp0 (transport, "UDP") == 0) {
    candidate = nice_candidate_new(ntype);
    candidate->component_id = component_id;
    candidate->stream_id = stream_id;
    candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
    g_strlcpy(candidate->foundation, foundation, NICE_CANDIDATE_MAX_FOUNDATION);
    candidate->priority = priority;

    if (!nice_address_set_from_string (&candidate->addr, addr)) {
      nice_candidate_free (candidate);
      candidate = NULL;
      goto done;
    }
    nice_address_set_port (&candidate->addr, port);

    if (raddr && rport) {
      if (!nice_address_set_from_string (&candidate->base_addr, raddr)) {
        nice_candidate_free (candidate);
        candidate = NULL;
        goto done;
      }
      nice_address_set_port (&candidate->base_addr, rport);
    }
  }

 done:
  if (tokens)
    g_strfreev(tokens);

  return candidate;
}


NICEAPI_EXPORT GIOStream *
nice_agent_get_io_stream (NiceAgent *agent, guint stream_id,
    guint component_id)
{
  GIOStream *iostream = NULL;
  Component *component;

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (component_id >= 1, NULL);

  g_return_val_if_fail (agent->reliable, NULL);

  agent_lock ();

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    goto done;

  if (component->iostream == NULL)
    component->iostream = nice_io_stream_new (agent, stream_id, component_id);

  iostream = g_object_ref (component->iostream);

 done:
  agent_unlock_and_emit (agent);

  return iostream;
}
