/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2010 Collabora Ltd.
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

#include "stream.h"
#include "interfaces.h"

#include "pseudotcp.h"

/* This is the max size of a UDP packet
 * will it work tcp relaying??
 */
#define MAX_BUFFER_SIZE 65536
#define DEFAULT_STUN_PORT  3478
#define DEFAULT_UPNP_TIMEOUT 200

#define MAX_TCP_MTU 1400 /* Use 1400 because of VPNs and we assume IEE 802.3 */

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
  N_SIGNALS,
};

static guint signals[N_SIGNALS];

#if GLIB_CHECK_VERSION(2,31,8)
static GRecMutex agent_mutex;    /* Mutex used for thread-safe lib */
#else
static GStaticRecMutex agent_mutex = G_STATIC_REC_MUTEX_INIT;
#endif

static gboolean priv_attach_stream_component (NiceAgent *agent,
    Stream *stream,
    Component *component);
static void priv_detach_stream_component (Stream *stream, Component *component);

static void priv_free_upnp (NiceAgent *agent);

#if GLIB_CHECK_VERSION(2,31,8)
void agent_lock (void)
{
  g_rec_mutex_lock (&agent_mutex);
}

void agent_unlock (void)
{
  g_rec_mutex_unlock (&agent_mutex);
}

#else
void agent_lock(void)
{
  g_static_rec_mutex_lock (&agent_mutex);
}

void agent_unlock(void)
{
  g_static_rec_mutex_unlock (&agent_mutex);
}

#endif

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

  agent_unlock();
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

  agent_unlock();

}


static void priv_destroy_component_tcp (Component *component)
{
    if (component->tcp_clock) {
      g_source_destroy (component->tcp_clock);
      g_source_unref (component->tcp_clock);
      component->tcp_clock = NULL;
    }
    if (component->tcp) {
      pseudo_tcp_socket_close (component->tcp, TRUE);
      g_object_unref (component->tcp);
      component->tcp = NULL;
    }
    if (component->tcp_data != NULL) {
      g_slice_free (TcpUserData, component->tcp_data);
      component->tcp_data = NULL;
    }
}

static void priv_pseudo_tcp_error (NiceAgent *agent, Stream *stream,
    Component *component)
{
  if (component->tcp) {
    agent_signal_component_state_change (agent, stream->id,
        component->id, NICE_COMPONENT_STATE_FAILED);
    priv_detach_stream_component (stream, component);
  }
  priv_destroy_component_tcp (component);
}

static void
adjust_tcp_clock (NiceAgent *agent, Stream *stream, Component *component);


static void
pseudo_tcp_socket_opened (PseudoTcpSocket *sock, gpointer user_data)
{
  TcpUserData *data = (TcpUserData *)user_data;
  NiceAgent *agent = data->agent;
  Component *component = data->component;
  Stream *stream = data->stream;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket Opened", data->agent,
      stream->id, component->id);
  g_signal_emit (agent, signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE], 0,
      stream->id, component->id);
}

static void
pseudo_tcp_socket_readable (PseudoTcpSocket *sock, gpointer user_data)
{
  TcpUserData *data = (TcpUserData *)user_data;
  NiceAgent *agent = data->agent;
  Component *component = data->component;
  Stream *stream = data->stream;
  gchar buf[MAX_BUFFER_SIZE];
  gint len;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket readable", agent,
      stream->id, component->id);

  component->tcp_readable = TRUE;

  g_object_add_weak_pointer (G_OBJECT (sock), (gpointer *)&sock);
  g_object_add_weak_pointer (G_OBJECT (agent), (gpointer *)&agent);

  do {
    if (component->g_source_io_cb)
      len = pseudo_tcp_socket_recv (sock, buf, sizeof(buf));
    else
      len = 0;

    if (len > 0) {
      gpointer data = component->data;
      gint sid = stream->id;
      gint cid = component->id;
      NiceAgentRecvFunc callback = component->g_source_io_cb;
      /* Unlock the agent before calling the callback */
      agent_unlock();
      callback (agent, sid, cid, len, buf, data);
      agent_lock();
      if (sock == NULL) {
        nice_debug ("PseudoTCP socket got destroyed in readable callback!");
        break;
      }
    } else if (len < 0 &&
        pseudo_tcp_socket_get_error (sock) != EWOULDBLOCK) {
      /* Signal error */
      priv_pseudo_tcp_error (agent, stream, component);
    } else if (len < 0 &&
        pseudo_tcp_socket_get_error (sock) == EWOULDBLOCK){
      component->tcp_readable = FALSE;
    }
  } while (len > 0);

  if (agent) {
    adjust_tcp_clock (agent, stream, component);
    g_object_remove_weak_pointer (G_OBJECT (agent), (gpointer *)&agent);
  } else {
    nice_debug ("Not calling adjust_tcp_clock.. agent got destroyed!");
  }
  if (sock)
    g_object_remove_weak_pointer (G_OBJECT (sock), (gpointer *)&sock);
}

static void
pseudo_tcp_socket_writable (PseudoTcpSocket *sock, gpointer user_data)
{
  TcpUserData *data = (TcpUserData *)user_data;
  NiceAgent *agent = data->agent;
  Component *component = data->component;
  Stream *stream = data->stream;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket writable", data->agent,
      data->stream->id, data->component->id);
  g_signal_emit (agent, signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE], 0,
      stream->id, component->id);
}

static void
pseudo_tcp_socket_closed (PseudoTcpSocket *sock, guint32 err,
    gpointer user_data)
{
  TcpUserData *data = (TcpUserData *)user_data;
  NiceAgent *agent = data->agent;
  Component *component = data->component;
  Stream *stream = data->stream;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket closed",  agent,
      stream->id, component->id);
  priv_pseudo_tcp_error (agent, stream, component);
}


static PseudoTcpWriteResult
pseudo_tcp_socket_write_packet (PseudoTcpSocket *sock,
    const gchar *buffer, guint32 len, gpointer user_data)
{
  TcpUserData *data = (TcpUserData *)user_data;
  Component *component = data->component;

  if (component->selected_pair.local != NULL) {
    NiceSocket *sock;
    NiceAddress *addr;

#ifndef NDEBUG
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (&component->selected_pair.remote->addr, tmpbuf);

    nice_debug ("Agent %p : s%d:%d: sending %d bytes to [%s]:%d", data->agent,
        data->stream->id, component->id, len, tmpbuf,
        nice_address_get_port (&component->selected_pair.remote->addr));
#endif

    sock = component->selected_pair.local->sockptr;
    addr = &component->selected_pair.remote->addr;
    if (nice_socket_send (sock, addr, len, buffer)) {
      return WR_SUCCESS;
    }
  }

  return WR_FAIL;
}


static gboolean
notify_pseudo_tcp_socket_clock (gpointer user_data)
{
  TcpUserData *data = (TcpUserData *)user_data;
  Component *component = data->component;
  Stream *stream = data->stream;
  NiceAgent *agent = data->agent;

  agent_lock();

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in notify_pseudo_tcp_socket_clock");
    agent_unlock ();
    return FALSE;
  }
  if (component->tcp_clock) {
    g_source_destroy (component->tcp_clock);
    g_source_unref (component->tcp_clock);
    component->tcp_clock = NULL;
  }

  pseudo_tcp_socket_notify_clock (component->tcp);
  adjust_tcp_clock (agent, stream, component);

  agent_unlock();

  return FALSE;
}

static void
adjust_tcp_clock (NiceAgent *agent, Stream *stream, Component *component)
{
  long timeout = 0;
  if (component->tcp) {
    if (pseudo_tcp_socket_get_next_clock (component->tcp, &timeout)) {
      if (component->tcp_clock) {
        g_source_destroy (component->tcp_clock);
        g_source_unref (component->tcp_clock);
        component->tcp_clock = NULL;
      }
      component->tcp_clock = agent_timeout_add_with_context (agent,
          timeout, notify_pseudo_tcp_socket_clock, component->tcp_data);
    } else {
      nice_debug ("Agent %p: component %d pseudo tcp socket should be destroyed",
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
    pseudo_tcp_socket_connect (component->tcp);
    pseudo_tcp_socket_notify_mtu (component->tcp, MAX_TCP_MTU);
    adjust_tcp_clock (agent, stream, component);
  } else if(agent->reliable) {
    nice_debug ("New selected pair received when pseudo tcp socket in error");
    return;
  }

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
        break;
    }

  return "invalid";
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
        agent_attach_stream_component_socket (agent, stream,
            component, new_socket);
        component->sockets= g_slist_append (component->sockets, new_socket);
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

    agent_attach_stream_component_socket (agent, stream,
        component, cdisco->nicesock);
    component->sockets = g_slist_append (component->sockets, cdisco->nicesock);
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
  stream = stream_new (n_components);

  agent->streams = g_slist_append (agent->streams, stream);
  stream->id = agent->next_stream_id++;
  nice_debug ("Agent %p : allocating stream id %u (%p)", agent, stream->id, stream);
  if (agent->reliable) {
    nice_debug ("Agent %p : reliable stream", agent);
    for (i = 0; i < n_components; i++) {
      Component *component = stream_find_component_by_id (stream, i + 1);
      if (component) {
        TcpUserData *data = g_slice_new0 (TcpUserData);
        PseudoTcpCallbacks tcp_callbacks = {data,
                                            pseudo_tcp_socket_opened,
                                            pseudo_tcp_socket_readable,
                                            pseudo_tcp_socket_writable,
                                            pseudo_tcp_socket_closed,
                                            pseudo_tcp_socket_write_packet};
        data->agent = agent;
        data->stream = stream;
        data->component = component;
        component->tcp_data = data;
        component->tcp = pseudo_tcp_socket_new (0, &tcp_callbacks);
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

  agent_unlock();
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
      agent_unlock();
      return FALSE;
    }


    turn->username = g_strdup (username);
    turn->password = g_strdup (password);
    turn->type = type;

    nice_debug ("Agent %p: added relay server [%s]:%d of type %d", agent,
        server_ip, server_port, type);

    component->turn_servers = g_list_append (component->turn_servers, turn);
  }

  agent_unlock();
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

  agent_unlock();
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

  agent_unlock();
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

  agent_unlock();
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
    agent_unlock();
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

      if (component == NULL)
        continue;

      current_port = component->min_port;

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
        if (current_port == 0 || current_port > component->max_port)
          break;
      }
      nice_address_set_port (addr, 0);

      if (!host_candidate) {
        gchar ip[NICE_ADDRESS_STRING_LEN];
        nice_address_to_string (addr, ip);
        nice_debug ("Agent %p: Unable to add local host candidate %s for s%d:%d"
            ". Invalid interface?", agent, ip, stream->id, component->id);
        ret = FALSE;
        goto error;
      }

#ifdef HAVE_GUPNP
      if (agent->upnp_enabled) {
        NiceAddress *addr = nice_address_dup (&host_candidate->base_addr);
        nice_debug ("Agent %p: Adding UPnP port %s:%d", agent, local_ip,
            nice_address_get_port (&host_candidate->base_addr));
        gupnp_simple_igd_add_port (GUPNP_SIMPLE_IGD (agent->upnp), "UDP",
            0, local_ip, nice_address_get_port (&host_candidate->base_addr),
            0, PACKAGE_STRING);
        agent->upnp_mapping = g_slist_prepend (agent->upnp_mapping, addr);
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

      priv_detach_stream_component (stream, component);

      for (i = component->local_candidates; i; i = i->next) {
        NiceCandidate *candidate = i->data;
        nice_candidate_free (candidate);
      }
      for (i = component->sockets; i; i = i->next) {
        NiceSocket *udpsocket = i->data;
        nice_socket_free (udpsocket);
      }
      g_slist_free (component->local_candidates);
      component->local_candidates = NULL;
      g_slist_free (component->sockets);
      component->sockets = NULL;
    }
    discovery_prune_stream (agent, stream_id);
  }

  agent_unlock();

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
  /* note that streams/candidates can be in use by other threads */

  Stream *stream;

  agent_lock();
  stream = agent_find_stream (agent, stream_id);

  if (!stream) {
    goto done;
  }

  /* note: remove items with matching stream_ids from both lists */
  conn_check_prune_stream (agent, stream);
  discovery_prune_stream (agent, stream_id);
  refresh_prune_stream (agent, stream_id);

  /* remove the stream itself */
  agent->streams = g_slist_remove (agent->streams, stream);
  stream_free (stream);

  if (!agent->streams)
    priv_remove_keepalive_timer (agent);

 done:
  agent_unlock();
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

  agent_unlock();
}

NICEAPI_EXPORT gboolean
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr)
{
  NiceAddress *dup;

  agent_lock();

  dup = nice_address_dup (addr);
  nice_address_set_port (dup, 0);
  agent->local_addresses = g_slist_append (agent->local_addresses, dup);

  agent_unlock();
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
    {
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

    {
      gchar tmpbuf[INET6_ADDRSTRLEN] = {0};
      if(addr)
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
  agent_unlock();
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

  agent_unlock();
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
  agent_unlock();

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
        g_socket_get_fd (socket->fileno), tmpbuf, nice_address_get_port (&from), len);
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

  agent->media_after_tick = TRUE;

  if (stun_message_validate_buffer_length ((uint8_t *) buf, (size_t) len,
      (agent->compatibility != NICE_COMPATIBILITY_OC2007 &&
       agent->compatibility != NICE_COMPATIBILITY_OC2007R2)) != len)
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
  gint ret = -1;

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component)) {
    goto done;
  }

  if (component->tcp != NULL) {
    ret = pseudo_tcp_socket_send (component->tcp, buf, len);
    adjust_tcp_clock (agent, stream, component);
    /*
    if (ret == -1 &&
        pseudo_tcp_socket_get_error (component->tcp) != EWOULDBLOCK) {
        }
    */
    /* In case of -1, the error is either EWOULDBLOCK or ENOTCONN, which both
       need the user to wait for the reliable-transport-writable signal */
  } else if(agent->reliable) {
    nice_debug ("Trying to send on a pseudo tcp FAILED component");
    goto done;
  } else if (component->selected_pair.local != NULL) {
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
  agent_unlock();
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

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    goto done;
  }

  for (item = component->local_candidates; item; item = item->next)
    ret = g_slist_append (ret, nice_candidate_copy (item->data));

 done:
  agent_unlock();
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
  agent_unlock();
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

  agent_unlock();
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


typedef struct _IOCtx IOCtx;

struct _IOCtx
{
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
  GSource *source)
{
  IOCtx *ctx;

  ctx = g_slice_new0 (IOCtx);
  ctx->agent = agent;
  ctx->stream = stream;
  ctx->component = component;
  ctx->socket = socket;
  ctx->source = source;

  return ctx;
}


static void
io_ctx_free (IOCtx *ctx)
{
  g_slice_free (IOCtx, ctx);
}

static gboolean
nice_agent_g_source_cb (
  GSocket *gsocket,
  GIOCondition condition,
  gpointer data)
{
  IOCtx *ctx = data;
  NiceAgent *agent = ctx->agent;
  Stream *stream = ctx->stream;
  Component *component = ctx->component;
  gchar buf[MAX_BUFFER_SIZE];
  gint len;

  agent_lock();

  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock ();
    return FALSE;
  }

  len = _nice_agent_recv (agent, stream, component, ctx->socket,
			  MAX_BUFFER_SIZE, buf);

  if (len > 0 && component->tcp) {
    g_object_add_weak_pointer (G_OBJECT (agent), (gpointer *)&agent);
    pseudo_tcp_socket_notify_packet (component->tcp, buf, len);
    if (agent) {
      adjust_tcp_clock (agent, stream, component);
      g_object_remove_weak_pointer (G_OBJECT (agent), (gpointer *)&agent);
    } else {
      nice_debug ("Our agent got destroyed in notify_packet!!");
    }
  } else if(len > 0 && agent->reliable) {
    nice_debug ("Received data on a pseudo tcp FAILED component");
  } else if (len > 0 && component->g_source_io_cb) {
    gpointer data = component->data;
    gint sid = stream->id;
    gint cid = component->id;
    NiceAgentRecvFunc callback = component->g_source_io_cb;
    /* Unlock the agent before calling the callback */
    agent_unlock();
    callback (agent, sid, cid, len, buf, data);
    goto done;
  } else if (len < 0) {
    GSource *source = ctx->source;

    nice_debug ("Agent %p: _nice_agent_recv returned %d, errno (%d) : %s",
        agent, len, errno, g_strerror (errno));
    component->gsources = g_slist_remove (component->gsources, source);
    g_source_destroy (source);
    g_source_unref (source);
    /* We don't close the socket because it would be way too complicated to
     * take care of every path where the socket might still be used.. */
    nice_debug ("Agent %p: unable to recv from socket %p. Detaching", agent,
        ctx->socket);

  }

  agent_unlock();

 done:

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
  GSource *source;
  IOCtx *ctx;

  if (!component->ctx)
    return;

  /* note: without G_IO_ERR the glib mainloop goes into
   *       busyloop if errors are encountered */
  source = g_socket_create_source(socket->fileno, G_IO_IN | G_IO_ERR, NULL);

  ctx = io_ctx_new (agent, stream, component, socket, source);
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

  agent_lock();

  /* attach candidates */

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    g_warning ("Could not find component %u in stream %u", component_id,
        stream_id);
    goto done;
  }

  if (component->g_source_io_cb)
    priv_detach_stream_component (stream, component);

  ret = TRUE;

  component->g_source_io_cb = NULL;
  component->data = NULL;
  if (component->ctx)
    g_main_context_unref (component->ctx);
  component->ctx = NULL;

  if (func) {
    component->g_source_io_cb = func;
    component->data = data;
    component->ctx = ctx;
    if (ctx)
      g_main_context_ref (ctx);

    priv_attach_stream_component (agent, stream, component);

    /* If we got detached, maybe our readable callback didn't finish reading
     * all available data in the pseudotcp, so we need to make sure we free
     * our recv window, so the readable callback can be triggered again on the
     * next incoming data.
     * but only do this if we know we're already readable, otherwise we might
     * trigger an error in the initial, pre-connection attach. */
    if (component->tcp && component->tcp_data && component->tcp_readable)
      pseudo_tcp_socket_readable (component->tcp, component->tcp_data);

  }

 done:
  agent_unlock();
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
  agent_unlock();
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
  agent_unlock();

  return ret;
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
  agent_unlock();
  return ret;
}

void
_priv_set_socket_tos (NiceAgent *agent, NiceSocket *sock, gint tos)
{
  if (setsockopt (g_socket_get_fd (sock->fileno), IPPROTO_IP,
          IP_TOS, (const char *) &tos, sizeof (tos)) < 0) {
    nice_debug ("Agent %p: Could not set socket ToS", agent,
        g_strerror (errno));
  }
#ifdef IPV6_TCLASS
  if (setsockopt (g_socket_get_fd (sock->fileno), IPPROTO_IPV6,
          IPV6_TCLASS, (const char *) &tos, sizeof (tos)) < 0) {
    nice_debug ("Agent %p: Could not set IPV6 socket ToS", agent,
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
  agent_unlock();
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

  agent_unlock ();
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
  agent_unlock();

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
  agent_unlock();
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
  agent_unlock ();

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

  agent_unlock();

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
  agent_unlock();

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

  agent_unlock();

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

  agent_unlock();

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

  agent_unlock();

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
  guint16 rport;
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
