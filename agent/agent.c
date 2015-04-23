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
#include "iostream.h"

#include "stream.h"
#include "interfaces.h"

#include "pseudotcp.h"

/* Maximum size of a UDP packet’s payload, as the packet’s length field is 16b
 * wide. */
#define MAX_BUFFER_SIZE ((1 << 16) - 1)  /* 65535 */

#define DEFAULT_STUN_PORT  3478
#define DEFAULT_UPNP_TIMEOUT 200  /* milliseconds */

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
  PROP_RELIABLE,
  PROP_ICE_UDP,
  PROP_ICE_TCP,
  PROP_BYTESTREAM_TCP,
  PROP_KEEPALIVE_CONNCHECK
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
  SIGNAL_NEW_SELECTED_PAIR_FULL,
  SIGNAL_NEW_CANDIDATE_FULL,
  SIGNAL_NEW_REMOTE_CANDIDATE_FULL,

  N_SIGNALS,
};

static guint signals[N_SIGNALS];

#if GLIB_CHECK_VERSION(2,31,8)
static GMutex agent_mutex;    /* Mutex used for thread-safe lib */
#else
static GStaticMutex agent_mutex = G_STATIC_MUTEX_INIT;
#endif

static void priv_stop_upnp (NiceAgent *agent);

static void pseudo_tcp_socket_opened (PseudoTcpSocket *sock, gpointer user_data);
static void pseudo_tcp_socket_readable (PseudoTcpSocket *sock, gpointer user_data);
static void pseudo_tcp_socket_writable (PseudoTcpSocket *sock, gpointer user_data);
static void pseudo_tcp_socket_closed (PseudoTcpSocket *sock, guint32 err,
    gpointer user_data);
static PseudoTcpWriteResult pseudo_tcp_socket_write_packet (PseudoTcpSocket *sock,
    const gchar *buffer, guint32 len, gpointer user_data);
static void adjust_tcp_clock (NiceAgent *agent, Stream *stream, Component *component);

static void nice_agent_dispose (GObject *object);
static void nice_agent_get_property (GObject *object,
  guint property_id, GValue *value, GParamSpec *pspec);
static void nice_agent_set_property (GObject *object,
  guint property_id, const GValue *value, GParamSpec *pspec);

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

static GType _nice_agent_stream_ids_get_type (void);

G_DEFINE_POINTER_TYPE (_NiceAgentStreamIds, _nice_agent_stream_ids);

#define NICE_TYPE_AGENT_STREAM_IDS _nice_agent_stream_ids_get_type ()

typedef struct {
  guint signal_id;
  GSignalQuery query;
  GValue *params;
} QueuedSignal;


static void
free_queued_signal (QueuedSignal *sig)
{
  guint i;

  g_value_unset (&sig->params[0]);

  for (i = 0; i < sig->query.n_params; i++) {
    if (G_VALUE_HOLDS(&sig->params[i + 1], NICE_TYPE_AGENT_STREAM_IDS))
      g_free (g_value_get_pointer (&sig->params[i + 1]));
    g_value_unset (&sig->params[i + 1]);
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
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

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
   * The maximum amount of time (in milliseconds) to wait for UPnP discovery to
   * finish before signaling the #NiceAgent::candidate-gathering-done signal
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
   * Whether the agent is providing a reliable transport of messages (through
   * ICE-TCP or PseudoTCP over ICE-UDP)
   *
   * Since: 0.0.11
   */
   g_object_class_install_property (gobject_class, PROP_RELIABLE,
      g_param_spec_boolean (
        "reliable",
        "reliable mode",
        "Whether the agent provides a reliable transport of messages",
	FALSE,
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  /**
   * NiceAgent:ice-udp:
   *
   * Whether the agent should use ICE-UDP when gathering candidates.
   * If the option is disabled, no UDP candidates will be generated. If the
   * agent is in reliable mode, then pseudotcp will not be used since pseudotcp
   * works on top of UDP candidates.
   * <para>
   * This option should be set before gathering candidates and should not be
   * modified afterwards.
   * </para>
   * The #NiceAgent:ice-udp property can be set at the same time as the
   * #NiceAgent:ice-tcp property, but both cannot be unset at the same time.
   * If #NiceAgent:ice-tcp is set to %FALSE, then this property cannot be set
   * to %FALSE as well.
   *
   * Since: 0.1.8
   */
   g_object_class_install_property (gobject_class, PROP_ICE_UDP,
      g_param_spec_boolean (
        "ice-udp",
        "Use ICE-UDP",
        "Use ICE-UDP specification to generate UDP candidates",
        TRUE, /* use ice-udp by default */
        G_PARAM_READWRITE));

  /**
   * NiceAgent:ice-tcp:
   *
   * Whether the agent should use ICE-TCP when gathering candidates.
   * If the option is disabled, no TCP candidates will be generated. If the
   * agent is in reliable mode, then pseudotcp will need to be used over UDP
   * candidates.
   * <para>
   * This option should be set before gathering candidates and should not be
   * modified afterwards.
   * </para>
   * The #NiceAgent:ice-tcp property can be set at the same time as the
   * #NiceAgent:ice-udp property, but both cannot be unset at the same time.
   * If #NiceAgent:ice-udp is set to %FALSE, then this property cannot be set
   * to %FALSE as well.
   * <note>
   <para>
   ICE-TCP is only supported for %NICE_COMPATIBILITY_RFC5245,
   %NICE_COMPATIBILITY_OC2007 and %NICE_COMPATIBILITY_OC2007R2 compatibility
   modes.
   </para>
   * </note>
   *
   * Since: 0.1.8
   */
   g_object_class_install_property (gobject_class, PROP_ICE_TCP,
      g_param_spec_boolean (
        "ice-tcp",
        "Use ICE-TCP",
        "Use ICE-TCP specification to generate TCP candidates",
        TRUE, /* use ice-tcp by default */
        G_PARAM_READWRITE));

  /**
   * NiceAgent:bytestream-tcp:
   *
   * This property defines whether receive/send over a TCP or pseudo-TCP, in
   * reliable mode, are considered as packetized or as bytestream.
   * In unreliable mode, every send/recv is considered as packetized, and
   * this property is ignored and cannot be set.
   * <para>
   * In reliable mode, this property will always return %TRUE in the
   * %NICE_COMPATIBILITY_GOOGLE compatibility mode.
   * </para>
   * If the property is %TRUE, the stream is considered in bytestream mode
   * and data can be read with any receive size. If the property is %FALSE, then
   * the stream is considred packetized and each receive will return one packet
   * of the same size as what was sent from the peer. If in packetized mode,
   * then doing a receive with a size smaller than the packet, will cause the
   * remaining bytes in the packet to be dropped, breaking the reliability
   * of the stream.
   * <para>
   * This property is currently read-only, and will become read/write once
   * bytestream mode will be supported.
   * </para>
   *
   * Since: 0.1.8
   */
   g_object_class_install_property (gobject_class, PROP_BYTESTREAM_TCP,
      g_param_spec_boolean (
        "bytestream-tcp",
        "Bytestream TCP",
        "Use bytestream mode for reliable TCP and Pseudo-TCP connections",
        FALSE,
        G_PARAM_READABLE));

  /**
   * NiceAgent:keepalive-conncheck:
   *
   * Use binding requests as keepalives instead of binding
   * indications. This means that the keepalives may time out which
   * will change the component state to %NICE_COMPONENT_STATE_FAILED.
   *
   * Enabing this is a slight violation of RFC 5245 section 10 which
   * recommends using Binding Indications for keepalives.
   *
   * This is always enabled if the compatibility mode is
   * %NICE_COMPATIBILITY_GOOGLE.
   *
   * Since: 0.1.8
   */
   g_object_class_install_property (gobject_class, PROP_KEEPALIVE_CONNCHECK,
      g_param_spec_boolean (
        "keepalive-conncheck",
        "Use conncheck as keepalives",
        "Use binding requests which require a reply as keepalives instead of "
        "binding indications which don't.",
	FALSE,
        G_PARAM_READWRITE));

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
          NULL,
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
          NULL,
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
   * This signal is fired once a candidate pair is selected for data
   * transfer for a stream's component This is emitted along with
   * #NiceAgent::new-selected-pair-full which has the whole candidate,
   * the Foundation of a Candidate is not a unique identifier.
   *
   * See also: #NiceAgent::new-selected-pair-full
   * Deprecated: 0.1.8: Use #NiceAgent::new-selected-pair-full
   */
  signals[SIGNAL_NEW_SELECTED_PAIR] =
      g_signal_new (
          "new-selected-pair",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          NULL,
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
   * This signal is fired when the agent discovers a new local candidate.
   * When this signal is emitted, a matching #NiceAgent::new-candidate-full is
   * also emitted with the candidate.
   *
   * See also: #NiceAgent::candidate-gathering-done,
   * #NiceAgent::new-candidate-full
   * Deprecated: 0.1.8: Use #NiceAgent::new-candidate-full
   */
  signals[SIGNAL_NEW_CANDIDATE] =
      g_signal_new (
          "new-candidate",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          NULL,
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
   * This signal is fired when the agent discovers a new remote
   * candidate.  This can happen with peer reflexive candidates.  When
   * this signal is emitted, a matching
   * #NiceAgent::new-remote-candidate-full is also emitted with the
   * candidate.
   *
   * See also: #NiceAgent::new-remote-candidate-full
   * Deprecated: 0.1.8: Use #NiceAgent::new-remote-candidate-full
   */
  signals[SIGNAL_NEW_REMOTE_CANDIDATE] =
      g_signal_new (
          "new-remote-candidate",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          NULL,
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
          NULL,
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
          NULL,
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
          NICE_TYPE_AGENT_STREAM_IDS,
          G_TYPE_INVALID);


  /**
   * NiceAgent::new-selected-pair-full
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @lcandidate: The local #NiceCandidate of the selected candidate pair
   * @rcandidate: The remote #NiceCandidate of the selected candidate pair
   *
   * This signal is fired once a candidate pair is selected for data
   * transfer for a stream's component. This is emitted along with
   * #NiceAgent::new-selected-pair.
   *
   * See also: #NiceAgent::new-selected-pair
   * Since: 0.1.8
   */
  signals[SIGNAL_NEW_SELECTED_PAIR_FULL] =
      g_signal_new (
          "new-selected-pair-full",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          NULL,
          G_TYPE_NONE,
          4, G_TYPE_UINT, G_TYPE_UINT, NICE_TYPE_CANDIDATE, NICE_TYPE_CANDIDATE,
          G_TYPE_INVALID);

  /**
   * NiceAgent::new-candidate-full
   * @agent: The #NiceAgent object
   * @candidate: The new #NiceCandidate
   *
   * This signal is fired when the agent discovers a new local candidate.
   * When this signal is emitted, a matching #NiceAgent::new-candidate is
   * also emitted with the candidate's foundation.
   *
   * See also: #NiceAgent::candidate-gathering-done,
   * #NiceAgent::new-candidate
   * Since: 0.1.8
   */
  signals[SIGNAL_NEW_CANDIDATE_FULL] =
      g_signal_new (
          "new-candidate-full",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          NULL,
          G_TYPE_NONE,
          1,
          NICE_TYPE_CANDIDATE,
          G_TYPE_INVALID);

  /**
   * NiceAgent::new-remote-candidate-full
   * @agent: The #NiceAgent object
   * @candidate: The new #NiceCandidate
   *
   * This signal is fired when the agent discovers a new remote candidate.
   * This can happen with peer reflexive candidates.
   * When this signal is emitted, a matching #NiceAgent::new-remote-candidate is
   * also emitted with the candidate's foundation.
   *
   * See also: #NiceAgent::new-remote-candidate
   * Since: 0.1.8
   */
  signals[SIGNAL_NEW_REMOTE_CANDIDATE_FULL] =
      g_signal_new (
          "new-remote-candidate-full",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          NULL,
          G_TYPE_NONE,
          1,
          NICE_TYPE_CANDIDATE,
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
  agent->use_ice_udp = TRUE;
  agent->use_ice_tcp = TRUE;

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

    case PROP_ICE_UDP:
      g_value_set_boolean (value, agent->use_ice_udp);
      break;

    case PROP_ICE_TCP:
      g_value_set_boolean (value, agent->use_ice_tcp);
      break;

    case PROP_BYTESTREAM_TCP:
      if (agent->reliable) {
        if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE)
          g_value_set_boolean (value, TRUE);
        else
          g_value_set_boolean (value, FALSE);
      } else {
        g_value_set_boolean (value, FALSE);
      }
      break;

    case PROP_KEEPALIVE_CONNCHECK:
      if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE)
        g_value_set_boolean (value, TRUE);
      else
        g_value_set_boolean (value, agent->keepalive_conncheck);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  agent_unlock_and_emit(agent);
}

void
nice_agent_init_stun_agent (NiceAgent *agent, StunAgent *stun_agent)
{
  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
  } else if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_FORCE_VALIDATER);
  } else if (agent->compatibility == NICE_COMPATIBILITY_WLM2009) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_WLM2009,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_USE_FINGERPRINT);
  } else if (agent->compatibility == NICE_COMPATIBILITY_OC2007) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_FORCE_VALIDATER |
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
  } else if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_WLM2009,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_USE_FINGERPRINT |
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
  } else {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC5389,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_USE_FINGERPRINT);
  }
  stun_agent_set_software (stun_agent, agent->software_attribute);
}

static void
nice_agent_reset_all_stun_agents (NiceAgent *agent, gboolean only_software)
{
  GSList *stream_item, *component_item;

  for (stream_item = agent->streams; stream_item;
       stream_item = stream_item->next) {
    Stream *stream = stream_item->data;

    for (component_item = stream->components; component_item;
         component_item = component_item->next) {
      Component *component = component_item->data;

      if (only_software)
        stun_agent_set_software (&component->stun_agent,
            agent->software_attribute);
      else
        nice_agent_init_stun_agent(agent, &component->stun_agent);
    }
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
      if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE ||
          agent->compatibility == NICE_COMPATIBILITY_MSN ||
          agent->compatibility == NICE_COMPATIBILITY_WLM2009)
        agent->use_ice_tcp = FALSE;

      nice_agent_reset_all_stun_agents (agent, FALSE);
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

      /* Don't allow ice-udp and ice-tcp to be disabled at the same time */
    case PROP_ICE_UDP:
      if (agent->use_ice_tcp == TRUE || g_value_get_boolean (value) == TRUE)
        agent->use_ice_udp = g_value_get_boolean (value);
      break;

    case PROP_ICE_TCP:
      if ((agent->compatibility == NICE_COMPATIBILITY_RFC5245 ||
              agent->compatibility == NICE_COMPATIBILITY_OC2007 ||
              agent->compatibility == NICE_COMPATIBILITY_OC2007R2) &&
          (agent->use_ice_udp == TRUE || g_value_get_boolean (value) == TRUE))
        agent->use_ice_tcp = g_value_get_boolean (value);
      break;

    case PROP_BYTESTREAM_TCP:
      /* TODO: support bytestream mode and set property to writable */
      break;

    case PROP_KEEPALIVE_CONNCHECK:
      agent->keepalive_conncheck = g_value_get_boolean (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  agent_unlock_and_emit (agent);

}


static void
 agent_signal_socket_writable (NiceAgent *agent, Component *component)
{
  g_cancellable_cancel (component->tcp_writable_cancellable);

  agent_queue_signal (agent, signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE],
      component->stream->id, component->id);
}

static void
pseudo_tcp_socket_create (NiceAgent *agent, Stream *stream, Component *component)
{
  PseudoTcpCallbacks tcp_callbacks = {component,
                                      pseudo_tcp_socket_opened,
                                      pseudo_tcp_socket_readable,
                                      pseudo_tcp_socket_writable,
                                      pseudo_tcp_socket_closed,
                                      pseudo_tcp_socket_write_packet};
  component->tcp = pseudo_tcp_socket_new (0, &tcp_callbacks);
  component->tcp_writable_cancellable = g_cancellable_new ();
  nice_debug ("Agent %p: Create Pseudo Tcp Socket for component %d",
      agent, component->id);
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
  }

  if (component->tcp_clock) {
    g_source_destroy (component->tcp_clock);
    g_source_unref (component->tcp_clock);
    component->tcp_clock = NULL;
  }
}

static void
pseudo_tcp_socket_opened (PseudoTcpSocket *sock, gpointer user_data)
{
  Component *component = user_data;
  NiceAgent *agent = component->agent;
  Stream *stream = component->stream;

  nice_debug ("Agent %p: s%d:%d pseudo Tcp socket Opened", agent,
      stream->id, component->id);

  agent_signal_socket_writable (agent, component);
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

        if (pseudo_tcp_socket_get_error (self) == ENOTCONN ||
            pseudo_tcp_socket_get_error (self) == EPIPE)
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
 * zero if no data is pending and the peer has disconnected), or a negative
 * number on error (including if the request would have blocked returning no
 * messages). */
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

        if (len == 0) {
          /* Reached EOS. */
          len = 0;
          goto done;
        } else if (len < 0 &&
            pseudo_tcp_socket_get_error (self) == EWOULDBLOCK) {
          /* EWOULDBLOCK. If we’ve already received something, return that;
           * otherwise, error. */
          if (nice_input_message_iter_get_n_valid_messages (iter) > 0) {
            goto done;
          }
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
              "Error reading data from pseudo-TCP socket: would block.");
          return len;
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
        /* Reached EOS. */
        component->tcp_readable = FALSE;
        pseudo_tcp_socket_close (component->tcp, FALSE);
        break;
      } else if (len < 0) {
        /* Handle errors. */
        if (pseudo_tcp_socket_get_error (sock) != EWOULDBLOCK) {
          nice_debug ("%s: calling priv_pseudo_tcp_error()", G_STRFUNC);
          priv_pseudo_tcp_error (agent, stream, component);
        }

        if (component->recv_buf_error != NULL) {
          GIOErrorEnum error_code;

          if (pseudo_tcp_socket_get_error (sock) == ENOTCONN)
            error_code = G_IO_ERROR_BROKEN_PIPE;
          else if (pseudo_tcp_socket_get_error (sock) == EWOULDBLOCK)
            error_code = G_IO_ERROR_WOULD_BLOCK;
          else
            error_code = G_IO_ERROR_FAILED;

          g_set_error (component->recv_buf_error, G_IO_ERROR, error_code,
              "Error reading data from pseudo-TCP socket.");
        }

        break;
      }

      component_emit_io_callback (component, buf, len);

      if (!agent_find_component (agent, stream_id, component_id,
              &stream, &component)) {
        nice_debug ("Stream or Component disappeared during the callback");
        goto out;
      }
      if (pseudo_tcp_socket_is_closed (component->tcp)) {
        nice_debug ("PseudoTCP socket got destroyed in readable callback!");
        goto out;
      }

      has_io_callback = component_has_io_callback (component);
    } while (has_io_callback);
  } else if (component->recv_messages != NULL) {
    gint n_valid_messages;
    GError *child_error = NULL;

    /* Fill up every buffer in every message until the connection closes or an
     * error occurs. Copy the data directly into the client’s receive message
     * array without making any callbacks. Update component->recv_messages_iter
     * as we go. */
    n_valid_messages = pseudo_tcp_socket_recv_messages (sock,
        component->recv_messages, component->n_recv_messages,
        &component->recv_messages_iter, &child_error);

    nice_debug ("%s: Client buffers case: Received %d valid messages:",
        G_STRFUNC, n_valid_messages);
    nice_debug_input_message_composition (component->recv_messages,
        component->n_recv_messages);

    if (n_valid_messages < 0) {
      g_propagate_error (component->recv_buf_error, child_error);
    } else {
      g_clear_error (&child_error);
    }

    if (n_valid_messages < 0 &&
        g_error_matches (child_error, G_IO_ERROR,
            G_IO_ERROR_WOULD_BLOCK)) {
      component->tcp_readable = FALSE;
    } else if (n_valid_messages < 0) {
      nice_debug ("%s: calling priv_pseudo_tcp_error()", G_STRFUNC);
      priv_pseudo_tcp_error (agent, stream, component);
    } else if (n_valid_messages == 0) {
      /* Reached EOS. */
      component->tcp_readable = FALSE;
      pseudo_tcp_socket_close (component->tcp, FALSE);
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

  agent_signal_socket_writable (agent, component);
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
pseudo_tcp_socket_write_packet (PseudoTcpSocket *psocket,
    const gchar *buffer, guint32 len, gpointer user_data)
{
  Component *component = user_data;

  if (component->selected_pair.local != NULL) {
    NiceSocket *sock;
    NiceAddress *addr;

    sock = component->selected_pair.local->sockptr;
    addr = &component->selected_pair.remote->addr;

    if (nice_debug_is_enabled ()) {
      gchar tmpbuf[INET6_ADDRSTRLEN];
      nice_address_to_string (addr, tmpbuf);

      nice_debug (
          "Agent %p : s%d:%d: sending %d bytes on socket %p (FD %d) to [%s]:%d",
          component->agent, component->stream->id, component->id, len,
          sock->fileno, g_socket_get_fd (sock->fileno), tmpbuf,
          nice_address_get_port (addr));
    }

    /* Send the segment. nice_socket_send() returns 0 on EWOULDBLOCK; in that
     * case the segment is not sent on the wire, but we return WR_SUCCESS
     * anyway. This effectively drops the segment. The pseudo-TCP state machine
     * will eventually pick up this loss and go into recovery mode, reducing
     * its transmission rate and, hopefully, the usage of system resources
     * which caused the EWOULDBLOCK in the first place. */
    if (nice_socket_send (sock, addr, len, buffer) >= 0) {
      return WR_SUCCESS;
    }
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
  Stream *stream;
  NiceAgent *agent;

  agent_lock();

  stream = component->stream;
  agent = component->agent;

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
  if (!pseudo_tcp_socket_is_closed (component->tcp)) {
    guint64 timeout = component->last_clock_timeout;

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
          long interval = timeout - (guint32) (g_get_monotonic_time () / 1000);

          /* Prevent integer overflows */
          if (interval < 0 || interval > G_MAXINT)
            interval = G_MAXINT;
          agent_timeout_add_with_context (agent, &component->tcp_clock,
              "Pseudo-TCP clock", interval,
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

static void
_tcp_sock_is_writable (NiceSocket *sock, gpointer user_data)
{
  Component *component = user_data;
  NiceAgent *agent = component->agent;
  Stream *stream = component->stream;

  agent_lock ();

  /* Don't signal writable if the socket that has become writable is not
   * the selected pair */
  if (component->selected_pair.local == NULL ||
      component->selected_pair.local->sockptr != sock) {
    agent_unlock ();
    return;
  }

  nice_debug ("Agent %p: s%d:%d Tcp socket writable", agent,
      stream->id, component->id);
  agent_signal_socket_writable (agent, component);

  agent_unlock_and_emit (agent);
}

static const gchar *
_transport_to_string (NiceCandidateTransport type) {
  switch(type) {
    case NICE_CANDIDATE_TRANSPORT_UDP:
      return "UDP";
    case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
      return "TCP-ACT";
    case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
      return "TCP-PASS";
    case NICE_CANDIDATE_TRANSPORT_TCP_SO:
      return "TCP-SO";
    default:
      return "???";
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
          nice_debug ("Agent %p: gathered %s local candidate : [%s]:%u"
              " for s%d/c%d. U/P '%s'/'%s'", agent,
              _transport_to_string (local_candidate->transport),
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
            conn_check_add_for_candidate_pair (agent, stream->id, component,
                local_candidate, remote_candidate);
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

  g_assert (agent->reliable);

  if (component->selected_pair.local == NULL ||
      pseudo_tcp_socket_is_closed (component->tcp) ||
      nice_socket_is_reliable (component->selected_pair.local->sockptr)) {
    return;
  }

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
    if (pseudo_tcp_socket_is_closed (component->tcp)) {
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

void agent_signal_new_selected_pair (NiceAgent *agent, guint stream_id,
    guint component_id, NiceCandidate *lcandidate, NiceCandidate *rcandidate)
{
  Component *component;
  Stream *stream;

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    return;

  if (((NiceSocket *)lcandidate->sockptr)->type == NICE_SOCKET_TYPE_UDP_TURN) {
    nice_udp_turn_socket_set_peer (lcandidate->sockptr, &rcandidate->addr);
  }

  if(agent->reliable && !nice_socket_is_reliable (lcandidate->sockptr)) {
    if (!component->tcp)
      pseudo_tcp_socket_create (agent, stream, component);
    process_queued_tcp_packets (agent, stream, component);

    pseudo_tcp_socket_connect (component->tcp);
    pseudo_tcp_socket_notify_mtu (component->tcp, MAX_TCP_MTU);
    adjust_tcp_clock (agent, stream, component);
  }

  if (nice_debug_is_enabled ()) {
    gchar ip[100];
    guint port;

    port = nice_address_get_port (&lcandidate->addr);
    nice_address_to_string (&lcandidate->addr, ip);

    nice_debug ("Agent %p: Local selected pair: %d:%d %s %s %s:%d %s",
        agent, stream_id, component_id, lcandidate->foundation,
        lcandidate->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ?
        "TCP-ACT" :
        lcandidate->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE ?
        "TCP-PASS" :
        lcandidate->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "UDP" : "???",
        ip, port, lcandidate->type == NICE_CANDIDATE_TYPE_HOST ? "HOST" :
        lcandidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ?
        "SRV-RFLX" :
        lcandidate->type == NICE_CANDIDATE_TYPE_RELAYED ?
        "RELAYED" :
        lcandidate->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE ?
        "PEER-RFLX" : "???");

    port = nice_address_get_port (&rcandidate->addr);
    nice_address_to_string (&rcandidate->addr, ip);

    nice_debug ("Agent %p: Remote selected pair: %d:%d %s %s %s:%d %s",
        agent, stream_id, component_id, rcandidate->foundation,
        rcandidate->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ?
        "TCP-ACT" :
        rcandidate->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE ?
        "TCP-PASS" :
        rcandidate->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "UDP" : "???",
        ip, port, rcandidate->type == NICE_CANDIDATE_TYPE_HOST ? "HOST" :
        rcandidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ?
        "SRV-RFLX" :
        rcandidate->type == NICE_CANDIDATE_TYPE_RELAYED ?
        "RELAYED" :
        rcandidate->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE ?
        "PEER-RFLX" : "???");
  }

  agent_queue_signal (agent, signals[SIGNAL_NEW_SELECTED_PAIR_FULL],
      stream_id, component_id, lcandidate, rcandidate);
  agent_queue_signal (agent, signals[SIGNAL_NEW_SELECTED_PAIR],
      stream_id, component_id, lcandidate->foundation, rcandidate->foundation);

  if(agent->reliable && nice_socket_is_reliable (lcandidate->sockptr)) {
    agent_signal_socket_writable (agent, component);
  }
}

void agent_signal_new_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  agent_queue_signal (agent, signals[SIGNAL_NEW_CANDIDATE_FULL],
      candidate);
  agent_queue_signal (agent, signals[SIGNAL_NEW_CANDIDATE],
      candidate->stream_id, candidate->component_id, candidate->foundation);
}

void agent_signal_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  agent_queue_signal (agent, signals[SIGNAL_NEW_REMOTE_CANDIDATE_FULL],
      candidate);
  agent_queue_signal (agent, signals[SIGNAL_NEW_REMOTE_CANDIDATE],
      candidate->stream_id, candidate->component_id, candidate->foundation);
}

NICEAPI_EXPORT const gchar *
nice_component_state_to_string (NiceComponentState state)
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

  if (component->state != state && state < NICE_COMPONENT_STATE_LAST) {
    nice_debug ("Agent %p : stream %u component %u STATE-CHANGE %s -> %s.", agent,
        stream_id, component_id, nice_component_state_to_string (component->state),
        nice_component_state_to_string (state));

    component->state = state;

    if (agent->reliable)
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
    NiceSocket *nicesock, NiceAddress server,
    Stream *stream, guint component_id)
{
  CandidateDiscovery *cdisco;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);

  cdisco->type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
  cdisco->nicesock = nicesock;
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
    NiceSocket *nicesock, TurnServer *turn,
    Stream *stream, guint component_id, gboolean turn_tcp)
{
  CandidateDiscovery *cdisco;
  Component *component = stream_find_component_by_id (stream, component_id);
  NiceAddress local_address;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);
  cdisco->type = NICE_CANDIDATE_TYPE_RELAYED;

  if (turn->type == NICE_RELAY_TYPE_TURN_UDP) {
    if (agent->use_ice_udp == FALSE || turn_tcp == TRUE) {
      g_slice_free (CandidateDiscovery, cdisco);
      return;
    }
    if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
      NiceAddress addr = nicesock->addr;
      NiceSocket *new_socket;
      nice_address_set_port (&addr, 0);

      new_socket = nice_udp_bsd_socket_new (&addr);
      if (new_socket) {
        _priv_set_socket_tos (agent, new_socket, stream->tos);
        component_attach_socket (component, new_socket);
        nicesock = new_socket;
      }
    }
    cdisco->nicesock = nicesock;
  } else {
    NiceAddress proxy_server;
    gboolean reliable_tcp = FALSE;

    /* MS-TURN will allocate a transport with the same protocol it received
     * the allocate request. So if we are connecting in TCP, then the candidate
     * will be TCP-ACT/TCP-PASS which means it will be reliable all the way
     * to the peer.
     * [MS-TURN] : The transport address has the same transport protocol
     * over which the Allocate request was received; a request that is
     * received over TCP returns a TCP allocated transport address.
     */
    if (turn_tcp)
      reliable_tcp = TRUE;

    /* Ignore tcp candidates if we disabled ice-tcp */
    if ((agent->use_ice_udp == FALSE && reliable_tcp == FALSE) ||
        (agent->use_ice_tcp == FALSE && reliable_tcp == TRUE)) {
      g_slice_free (CandidateDiscovery, cdisco);
      return;
    }

    /* TURN-TCP is currently unsupport unless it's OC2007 compatibliity */
    /* TODO: Add support for TURN-TCP */
    if (((agent->compatibility == NICE_COMPATIBILITY_OC2007 ||
            agent->compatibility == NICE_COMPATIBILITY_OC2007R2) &&
            reliable_tcp == FALSE) ||
        (!(agent->compatibility == NICE_COMPATIBILITY_OC2007 ||
            agent->compatibility == NICE_COMPATIBILITY_OC2007R2) &&
            reliable_tcp == TRUE)) {
      g_slice_free (CandidateDiscovery, cdisco);
      return;
    }

    local_address = nicesock->addr;
    nice_address_set_port (&local_address, 0);
    nicesock = NULL;

    /* TODO: add support for turn-tcp RFC 6062 */
    if (agent->proxy_type != NICE_PROXY_TYPE_NONE &&
        agent->proxy_ip != NULL &&
        nice_address_set_from_string (&proxy_server, agent->proxy_ip)) {
      nice_address_set_port (&proxy_server, agent->proxy_port);
      nicesock = nice_tcp_bsd_socket_new (agent->main_context, &local_address,
          &proxy_server, reliable_tcp);

      if (nicesock) {
        _priv_set_socket_tos (agent, nicesock, stream->tos);
        if (agent->proxy_type == NICE_PROXY_TYPE_SOCKS5) {
          nicesock = nice_socks5_socket_new (nicesock, &turn->server,
              agent->proxy_username, agent->proxy_password);
        } else if (agent->proxy_type == NICE_PROXY_TYPE_HTTP){
          nicesock = nice_http_socket_new (nicesock, &turn->server,
              agent->proxy_username, agent->proxy_password);
        } else {
          nice_socket_free (nicesock);
          nicesock = NULL;
        }
      }

    }
    if (nicesock == NULL) {
      nicesock = nice_tcp_bsd_socket_new (agent->main_context, &local_address,
          &turn->server, reliable_tcp);

      if (nicesock)
        _priv_set_socket_tos (agent, nicesock, stream->tos);
    }

    /* The TURN server may be invalid or not listening */
    if (nicesock == NULL)
      return;

    if (agent->reliable)
      nice_socket_set_writable_callback (nicesock, _tcp_sock_is_writable,
          component);
    if (turn->type ==  NICE_RELAY_TYPE_TURN_TLS &&
        agent->compatibility == NICE_COMPATIBILITY_GOOGLE) {
      nicesock = nice_pseudossl_socket_new (nicesock,
          NICE_PSEUDOSSL_SOCKET_COMPATIBILITY_GOOGLE);
    } else if (turn->type == NICE_RELAY_TYPE_TURN_TLS &&
        (agent->compatibility == NICE_COMPATIBILITY_OC2007 ||
            agent->compatibility == NICE_COMPATIBILITY_OC2007R2)) {
      nicesock = nice_pseudossl_socket_new (nicesock,
          NICE_PSEUDOSSL_SOCKET_COMPATIBILITY_MSOC);
    }
    cdisco->nicesock = nice_udp_turn_over_tcp_socket_new (nicesock,
        agent_to_turn_socket_compatibility (agent));

    component_attach_socket (component, cdisco->nicesock);
  }

  cdisco->turn = turn_server_ref (turn);
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

  g_return_val_if_fail (NICE_IS_AGENT (agent), 0);
  g_return_val_if_fail (n_components >= 1, 0);

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
        pseudo_tcp_socket_create (agent, stream, component);
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
  Stream *stream = NULL;
  gboolean ret = TRUE;
  TurnServer *turn;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);
  g_return_val_if_fail (component_id >= 1, FALSE);
  g_return_val_if_fail (server_ip, FALSE);
  g_return_val_if_fail (server_port, FALSE);
  g_return_val_if_fail (username, FALSE);
  g_return_val_if_fail (password, FALSE);
  g_return_val_if_fail (type <= NICE_RELAY_TYPE_TURN_TLS, FALSE);

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id, &stream,
          &component)) {
    ret = FALSE;
    goto done;
  }

  turn = turn_server_new (server_ip, server_port, username, password, type);

  if (!turn) {
    ret = FALSE;
    goto done;
  }

  nice_debug ("Agent %p: added relay server [%s]:%d of type %d to s/c %d/%d "
      "with user/pass : %s -- %s", agent, server_ip, server_port, type,
      stream_id, component_id, username, password);

  component->turn_servers = g_list_append (component->turn_servers, turn);

 if (stream->gathering_started) {
    GSList *i;

    stream->gathering = TRUE;

    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *candidate = i->data;

      if  (candidate->type == NICE_CANDIDATE_TYPE_HOST &&
           candidate->transport != NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE)
        priv_add_new_candidate_discovery_turn (agent,
            candidate->sockptr, turn, stream, component_id,
            candidate->transport != NICE_CANDIDATE_TRANSPORT_UDP);
    }

    if (agent->discovery_unsched_items)
      discovery_schedule (agent);
  }


 done:

  agent_unlock_and_emit (agent);
  return ret;
}

#ifdef HAVE_GUPNP

static void agent_check_upnp_gathering_done (NiceAgent *agent);

static gboolean priv_upnp_timeout_cb (gpointer user_data)
{
  NiceAgent *agent = (NiceAgent*)user_data;

  agent_lock();

  /* If the source has been destroyed, we have already freed all mappings. */
  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock ();
    return FALSE;
  }

  nice_debug ("Agent %p : UPnP port mapping timed out", agent);

  /* We cannot free priv->upnp here as it may be holding mappings open which
   * we are using (e.g. if some mappings were successful and others errored). */
  g_slist_free_full (agent->upnp_mapping, (GDestroyNotify) nice_address_free);
  agent->upnp_mapping = NULL;

  agent_check_upnp_gathering_done (agent);

  agent_unlock_and_emit (agent);
  return FALSE;
}

/* Check whether UPnP gathering is done, which is true when the list of pending
 * mappings (upnp_mapping) is empty. When it is empty, we have heard back from
 * gupnp-igd about each of the mappings we added, either successfully or not.
 *
 * Note that upnp_mapping has to be a list, rather than a counter, as the
 * mapped-external-port and error-mapping-port signals could be emitted multiple
 * times for each mapping. */
static void agent_check_upnp_gathering_done (NiceAgent *agent)
{
  if (agent->upnp_mapping != NULL)
    return;

  if (agent->upnp_timer_source != NULL) {
    g_source_destroy (agent->upnp_timer_source);
    g_source_unref (agent->upnp_timer_source);
    agent->upnp_timer_source = NULL;
  }

  agent_gathering_done (agent);
}

static void _upnp_mapped_external_port (GUPnPSimpleIgd *self, gchar *proto,
    gchar *external_ip, gchar *replaces_external_ip, guint external_port,
    gchar *local_ip, guint local_port, gchar *description, gpointer user_data)
{
  NiceAgent *agent = (NiceAgent*)user_data;
  NiceAddress localaddr;
  NiceAddress externaddr;
  NiceCandidateTransport transport;
  GSList *i, *j, *k;

  agent_lock();

  if (agent->upnp_timer_source == NULL)
    goto end;

  nice_debug ("Agent %p : Successfully mapped %s:%d to %s:%d", agent, local_ip,
      local_port, external_ip, external_port);

  if (!nice_address_set_from_string (&localaddr, local_ip))
    goto end;
  nice_address_set_port (&localaddr, local_port);

  if (g_strcmp0 (proto, "TCP") == 0)
    transport = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
  else
    transport = NICE_CANDIDATE_TRANSPORT_UDP;

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
              transport,
              local_candidate->sockptr,
              TRUE);
          goto end;
        }
      }
    }
  }

 end:
  agent_check_upnp_gathering_done (agent);

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

    agent_check_upnp_gathering_done (agent);
  }

  agent_unlock_and_emit (agent);
}

#endif

NICEAPI_EXPORT gboolean
nice_agent_gather_candidates (
  NiceAgent *agent,
  guint stream_id)
{
  guint cid;
  GSList *i;
  Stream *stream;
  GSList *local_addresses = NULL;
  gboolean ret = TRUE;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    agent_unlock_and_emit (agent);
    return FALSE;
  }

  if (stream->gathering_started) {
    /* Stream is already gathering, ignore this call */
    agent_unlock_and_emit (agent);
    return TRUE;
  }

  nice_debug ("Agent %p : In %s mode, starting candidate gathering.", agent,
      agent->full_mode ? "ICE-FULL" : "ICE-LITE");

#ifdef HAVE_GUPNP
  if (agent->upnp_enabled && agent->upnp == NULL) {
    agent->upnp = gupnp_simple_igd_thread_new ();

    if (agent->upnp) {
      agent_timeout_add_with_context (agent, &agent->upnp_timer_source,
          "UPnP timeout", agent->upnp_timeout, priv_upnp_timeout_cb, agent);

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
      const gchar *addr_string = item->data;
      NiceAddress *addr = nice_address_new ();

      if (nice_address_set_from_string (addr, addr_string)) {
        local_addresses = g_slist_append (local_addresses, addr);
      } else {
        nice_debug ("Error: Failed to parse local address ‘%s’.", addr_string);
        nice_address_free (addr);
      }
    }

    g_list_foreach (addresses, (GFunc) g_free, NULL);
    g_list_free (addresses);
  } else {
    for (i = agent->local_addresses; i; i = i->next) {
      NiceAddress *addr = i->data;
      NiceAddress *dupaddr = nice_address_dup (addr);

      local_addresses = g_slist_append (local_addresses, dupaddr);
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

    for (cid = 1; cid <= stream->n_components; cid++) {
      Component *component = stream_find_component_by_id (stream, cid);
      enum {
        ADD_HOST_MIN = 0,
        ADD_HOST_UDP = ADD_HOST_MIN,
        ADD_HOST_TCP_ACTIVE,
        ADD_HOST_TCP_PASSIVE,
        ADD_HOST_MAX = ADD_HOST_TCP_PASSIVE
      } add_type;

      if (component == NULL)
        continue;

      for (add_type = ADD_HOST_MIN; add_type <= ADD_HOST_MAX; add_type++) {
        NiceCandidateTransport transport;
        guint current_port;
        guint start_port;
        HostCandidateResult res = HOST_CANDIDATE_CANT_CREATE_SOCKET;

        if ((agent->use_ice_udp == FALSE && add_type == ADD_HOST_UDP) ||
            (agent->use_ice_tcp == FALSE && add_type != ADD_HOST_UDP))
          continue;

        switch (add_type) {
          default:
          case ADD_HOST_UDP:
            transport = NICE_CANDIDATE_TRANSPORT_UDP;
            break;
          case ADD_HOST_TCP_ACTIVE:
            transport = NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
            break;
          case ADD_HOST_TCP_PASSIVE:
            transport = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
            break;
        }

        start_port = component->min_port;
        if(component->min_port != 0) {
          start_port = nice_rng_generate_int(agent->rng, component->min_port, component->max_port+1);
        }
        current_port = start_port;

        host_candidate = NULL;
        while (res == HOST_CANDIDATE_CANT_CREATE_SOCKET) {
          nice_debug ("Agent %p: Trying to create host candidate on port %d", agent, current_port);
          nice_address_set_port (addr, current_port);
          res =  discovery_add_local_host_candidate (agent, stream->id, cid,
              addr, transport, &host_candidate);
          if (current_port > 0)
            current_port++;
          if (current_port > component->max_port) current_port = component->min_port;
          if (current_port == 0 || current_port == start_port)
            break;
        }

        if (res == HOST_CANDIDATE_REDUNDANT) {
          nice_debug ("Agent %p: Ignoring local candidate, it's redundant",
                      agent);
          continue;
        } else if (res == HOST_CANDIDATE_FAILED) {
          nice_debug ("Agent %p: Could ot retrieive component %d/%d", agent,
              stream->id, cid);
          ret = FALSE;
          goto error;
        } else if (res == HOST_CANDIDATE_CANT_CREATE_SOCKET) {
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

        nice_address_set_port (addr, 0);


        if (agent->reliable)
          nice_socket_set_writable_callback (host_candidate->sockptr,
              _tcp_sock_is_writable, component);

#ifdef HAVE_GUPNP
      if (agent->upnp_enabled && agent->upnp &&
          transport != NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE) {
        NiceAddress *base_addr = nice_address_dup (&host_candidate->base_addr);
        nice_debug ("Agent %p: Adding UPnP port %s:%d", agent, local_ip,
            nice_address_get_port (base_addr));
        gupnp_simple_igd_add_port (GUPNP_SIMPLE_IGD (agent->upnp),
            transport == NICE_CANDIDATE_TRANSPORT_UDP ? "UDP" : "TCP",
            0, local_ip, nice_address_get_port (base_addr),
            0, PACKAGE_STRING);
        agent->upnp_mapping = g_slist_prepend (agent->upnp_mapping, base_addr);
      }
#endif

        /* TODO: Add server-reflexive support for TCP candidates */
        if (agent->full_mode && agent->stun_server_ip &&
            transport == NICE_CANDIDATE_TRANSPORT_UDP) {
          NiceAddress stun_server;
          if (nice_address_set_from_string (&stun_server, agent->stun_server_ip)) {
            nice_address_set_port (&stun_server, agent->stun_server_port);

            priv_add_new_candidate_discovery_stun (agent,
                host_candidate->sockptr,
                stun_server,
                stream,
                cid);
          }
        }

        if (agent->full_mode && component &&
            transport != NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE) {
          GList *item;

          for (item = component->turn_servers; item; item = item->next) {
            TurnServer *turn = item->data;

            priv_add_new_candidate_discovery_turn (agent,
                host_candidate->sockptr,
                turn,
                stream,
                cid,
                host_candidate->transport != NICE_CANDIDATE_TRANSPORT_UDP);
          }
        }
      }
    }
  }

  stream->gathering = TRUE;
  stream->gathering_started = TRUE;

  /* Only signal the new candidates after we're sure that the gathering was
   * succesfful. But before sending gathering-done */
  for (cid = 1; cid <= stream->n_components; cid++) {
    Component *component = stream_find_component_by_id (stream, cid);
    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *candidate = i->data;
      agent_signal_new_candidate (agent, candidate);
    }
  }

  /* note: no async discoveries pending, signal that we are ready */
  if (agent->discovery_unsched_items == 0 &&
#ifdef HAVE_GUPNP
      agent->upnp_mapping == NULL) {
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
    priv_stop_upnp (agent);
    for (cid = 1; cid <= stream->n_components; cid++) {
      Component *component = stream_find_component_by_id (stream, cid);

      component_free_socket_sources (component);

      for (i = component->local_candidates; i; i = i->next) {
        NiceCandidate *candidate = i->data;

        agent_remove_local_candidate (agent, candidate);

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

void agent_remove_local_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
#ifdef HAVE_GUPNP
  gchar local_ip[NICE_ADDRESS_STRING_LEN];

  if (agent->upnp == NULL)
    return;

  if (candidate->type != NICE_CANDIDATE_TYPE_HOST)
    return;

  nice_address_to_string (&candidate->addr, local_ip);

  gupnp_simple_igd_remove_port_local (GUPNP_SIMPLE_IGD (agent->upnp), "UDP",
      local_ip, nice_address_get_port (&candidate->addr));
#endif
}

static void priv_stop_upnp (NiceAgent *agent)
{
#ifdef HAVE_GUPNP
  if (!agent->upnp)
    return;

  g_slist_free_full (agent->upnp_mapping, (GDestroyNotify) nice_address_free);
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

  g_return_if_fail (NICE_IS_AGENT (agent));
  g_return_if_fail (stream_id >= 1);

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
  stream_close (stream);

  if (!agent->streams)
    priv_remove_keepalive_timer (agent);

  agent_queue_signal (agent, signals[SIGNAL_STREAMS_REMOVED],
      g_memdup (stream_ids, sizeof(stream_ids)));

  agent_unlock_and_emit (agent);

  /* Actually free the stream. This should be done with the lock released, as
   * it could end up disposing of a NiceIOStream, which tries to take the
   * agent lock itself. */
  stream_free (stream);

  return;
}

NICEAPI_EXPORT void
nice_agent_set_port_range (NiceAgent *agent, guint stream_id, guint component_id,
    guint min_port, guint max_port)
{
  Stream *stream;
  Component *component;

  g_return_if_fail (NICE_IS_AGENT (agent));
  g_return_if_fail (stream_id >= 1);
  g_return_if_fail (component_id >= 1);

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, &stream,
          &component)) {
    if (stream->gathering_started) {
      g_critical ("nice_agent_gather_candidates (stream_id=%u) already called for this stream", stream_id);
    } else {
      component->min_port = min_port;
      component->max_port = max_port;
    }
  }

  agent_unlock_and_emit (agent);
}

NICEAPI_EXPORT gboolean
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr)
{
  NiceAddress *dupaddr;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (addr != NULL, FALSE);

  agent_lock();

  dupaddr = nice_address_dup (addr);
  nice_address_set_port (dupaddr, 0);
  agent->local_addresses = g_slist_append (agent->local_addresses, dupaddr);

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
  }
  else {
    /* case 2: add a new candidate */

    if (type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
      nice_debug("Agent %p : Warning: ignoring externally set peer-reflexive candidate!", agent);
      return FALSE;
    }
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
      nice_debug ("Agent %p : Adding %s remote candidate with addr [%s]:%u"
          " for s%d/c%d. U/P '%s'/'%s' prio: %u", agent,
          _transport_to_string (transport), tmpbuf,
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
  }

  if (conn_check_add_for_candidate (agent, stream_id, component, candidate) < 0) {
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

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);

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
nice_agent_set_local_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar *ufrag,
  const gchar *pwd)
{
  Stream *stream;
  gboolean ret = FALSE;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);

  agent_lock ();

  stream = agent_find_stream (agent, stream_id);

  /* note: oddly enough, ufrag and pwd can be empty strings */
  if (stream && ufrag && pwd) {
    g_strlcpy (stream->local_ufrag, ufrag, NICE_STREAM_MAX_UFRAG);
    g_strlcpy (stream->local_password, pwd, NICE_STREAM_MAX_PWD);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);

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

  return added;
}


NICEAPI_EXPORT int
nice_agent_set_remote_candidates (NiceAgent *agent, guint stream_id, guint component_id, const GSList *candidates)
{
  int added = 0;
  Stream *stream;
  Component *component;

  g_return_val_if_fail (NICE_IS_AGENT (agent), 0);
  g_return_val_if_fail (stream_id >= 1, 0);
  g_return_val_if_fail (component_id >= 1, 0);

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
  NiceSocket *nicesock,
  NiceInputMessage *message)
{
  NiceAddress from;
  GList *item;
  gint retval;

  /* We need an address for packet parsing, below. */
  if (message->from == NULL) {
    message->from = &from;
  }

  /* ICE-TCP requires that all packets be framed with RFC4571 */
  if (nice_socket_is_reliable (nicesock)) {
    /* In the case of OC2007 and OC2007R2 which uses UDP TURN for TCP-ACTIVE
     * and TCP-PASSIVE candidates, the recv_messages will be packetized and
     * always return an entire frame, so we must read it as is */
    if (nicesock->type == NICE_SOCKET_TYPE_UDP_TURN_OVER_TCP ||
        nicesock->type == NICE_SOCKET_TYPE_UDP_TURN) {
      GSList *cand_i;
      GInputVector *local_bufs;
      NiceInputMessage local_message;
      guint n_bufs = 0;
      guint16 rfc4571_frame;
      guint i;

      /* In case of ICE-TCP on UDP-TURN (OC2007 compat), we need to do the recv
       * on the UDP_TURN socket, but it's possible we receive the source event
       * on the UDP_TURN_OVER_TCP socket, so in that case, we need to replace
       * the socket we do the recv on to the topmost socket
       */
      for (cand_i = component->local_candidates; cand_i; cand_i = cand_i->next) {
        NiceCandidate *cand = cand_i->data;

        if (cand->type == NICE_CANDIDATE_TYPE_RELAYED &&
            cand->stream_id == stream->id &&
            cand->component_id == component->id &&
            ((NiceSocket *)cand->sockptr)->fileno == nicesock->fileno) {
          nice_debug ("Agent %p : Packet received from a TURN socket.",
              agent);
          nicesock = cand->sockptr;
          break;
        }
      }
      /* Count the number of buffers. */
      if (message->n_buffers == -1) {
        for (i = 0; message->buffers[i].buffer != NULL; i++)
          n_bufs++;
      } else {
        n_bufs = message->n_buffers;
      }

      local_bufs = g_malloc_n (n_bufs + 1, sizeof (GInputVector));
      local_message.buffers = local_bufs;
      local_message.n_buffers = n_bufs + 1;
      local_message.from = message->from;
      local_message.length = 0;

      local_bufs[0].buffer = &rfc4571_frame;
      local_bufs[0].size = sizeof (guint16);

      for (i = 0; i < n_bufs; i++) {
        local_bufs[i + 1].buffer = message->buffers[i].buffer;
        local_bufs[i + 1].size = message->buffers[i].size;
      }
      retval = nice_socket_recv_messages (nicesock, &local_message, 1);
      if (retval == 1) {
        message->length = ntohs (rfc4571_frame);
      }
      g_free (local_bufs);
    } else {
      if (nicesock->type == NICE_SOCKET_TYPE_TCP_PASSIVE) {
        NiceSocket *new_socket;

        /* Passive candidates when readable should accept and create a new
         * socket. When established, the connchecks will create a peer reflexive
         * candidate for it */
        new_socket = nice_tcp_passive_socket_accept (nicesock);
        if (new_socket) {
          _priv_set_socket_tos (agent, new_socket, stream->tos);
          component_attach_socket (component, new_socket);
        }
        retval = 0;
      } else {
        /* In the case of a real ICE-TCP connection, we can use the socket as a
         * bytestream and do the read here with caching of data being read
         */
        gssize available = g_socket_get_available_bytes (nicesock->fileno);

        /* TODO: Support bytestream reads */
        message->length = 0;
        retval = 0;
        if (available <= 0) {
          retval = available;

          /* If we don't call check_connect_result on an outbound connection,
           * then is_connected will always return FALSE. That's why we check
           * both conditions to make sure g_socket_is_connected returns the
           * correct result, otherwise we end up closing valid connections
           */
          if (g_socket_check_connect_result (nicesock->fileno, NULL) == FALSE ||
              g_socket_is_connected (nicesock->fileno) == FALSE) {
            /* If we receive a readable event on a TCP_BSD socket which is
             * not connected, it means that it failed to connect, so we must
             * return an error to make the socket fail/closed
             */
            retval = -1;
          } else {
            gint flags = G_SOCKET_MSG_PEEK;

            /* If available bytes are 0, but the socket is still considered
             * connected, then either we're just trying to see if there's more
             * data available or the peer closed the connection.
             * The only way to know is to do a read, so we do here a peek and
             * check the return value, if it's 0, it means the peer has closed
             * the connection, so we must return an error instead of WOULD_BLOCK
             */
            if (g_socket_receive_message (nicesock->fileno, NULL,
                    NULL, 0, NULL, NULL, &flags, NULL, NULL) == 0)
              retval = -1;
          }
        } else if (agent->rfc4571_expecting_length == 0) {
          if ((gsize) available >= sizeof(guint16)) {
            guint16 rfc4571_frame;
            GInputVector local_buf = { &rfc4571_frame, sizeof(guint16)};
            NiceInputMessage local_message = { &local_buf, 1, message->from, 0};

            retval = nice_socket_recv_messages (nicesock, &local_message, 1);
            if (retval == 1) {
              agent->rfc4571_expecting_length = ntohs (rfc4571_frame);
              available = g_socket_get_available_bytes (nicesock->fileno);
            }
          }
        }
        if (agent->rfc4571_expecting_length > 0 &&
            available >= agent->rfc4571_expecting_length) {
          GInputVector *local_bufs;
          NiceInputMessage local_message;
          gsize off;
          guint n_bufs = 0;
          guint i;

          /* Count the number of buffers. */
          if (message->n_buffers == -1) {
            for (i = 0; message->buffers[i].buffer != NULL; i++)
              n_bufs++;
          } else {
            n_bufs = message->n_buffers;
          }

          local_bufs = g_malloc_n (n_bufs, sizeof (GInputVector));
          local_message.buffers = local_bufs;
          local_message.from = message->from;
          local_message.length = 0;
          local_message.n_buffers = 0;

          /* Only read up to the expected number of bytes in the frame */
          off = 0;
          for (i = 0; i < n_bufs; i++) {
            if (message->buffers[i].size < agent->rfc4571_expecting_length - off) {
              local_bufs[i].buffer = message->buffers[i].buffer;
              local_bufs[i].size = message->buffers[i].size;
              local_message.n_buffers++;
              off += message->buffers[i].size;
            } else {
              local_bufs[i].buffer = message->buffers[i].buffer;
              local_bufs[i].size = MIN (message->buffers[i].size,
                  agent->rfc4571_expecting_length - off);
              local_message.n_buffers++;
              off += local_bufs[i].size;
            }
          }
          retval = nice_socket_recv_messages (nicesock, &local_message, 1);
          if (retval == 1) {
            message->length = local_message.length;
            agent->rfc4571_expecting_length -= local_message.length;
          }
          g_free (local_bufs);
        }
      }
    }
  } else {
    retval = nice_socket_recv_messages (nicesock, message, 1);
  }

  nice_debug ("%s: Received %d valid messages of length %" G_GSIZE_FORMAT
      " from base socket %p.", G_STRFUNC, retval, message->length, nicesock);

  if (retval == 0) {
    retval = RECV_WOULD_BLOCK;  /* EWOULDBLOCK */
    goto done;
  } else if (retval < 0) {
    nice_debug ("Agent %p: %s returned %d, errno (%d) : %s",
        agent, G_STRFUNC, retval, errno, g_strerror (errno));

    retval = RECV_ERROR;
    goto done;
  }

  if (retval == RECV_OOB || message->length == 0) {
    retval = RECV_OOB;
    goto done;
  }

  if (nice_debug_is_enabled ()) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (message->from, tmpbuf);
    nice_debug ("Agent %p : Packet received on local socket %d from [%s]:%u (%" G_GSSIZE_FORMAT " octets).", agent,
        g_socket_get_fd (nicesock->fileno), tmpbuf,
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
        retval = nice_udp_turn_socket_parse_recv_message (cand->sockptr, &nicesock,
            message);
        break;
      }
    }
    break;
  }

  if (retval == RECV_OOB)
    goto done;

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
    int validated_len;

    big_buf = compact_input_message (message, &big_buf_len);

    validated_len = stun_message_validate_buffer_length (big_buf, big_buf_len,
        (agent->compatibility != NICE_COMPATIBILITY_OC2007 &&
         agent->compatibility != NICE_COMPATIBILITY_OC2007R2));

    if (validated_len == (gint) big_buf_len) {
      gboolean handled;

      handled =
        conn_check_handle_inbound_stun (agent, stream, component, nicesock,
            message->from, (gchar *) big_buf, big_buf_len);

      if (handled) {
        /* Handled STUN message. */
        nice_debug ("%s: Valid STUN packet received.", G_STRFUNC);
        retval = RECV_OOB;
        g_free (big_buf);
        goto done;
      }
    }

    nice_debug ("%s: Packet passed fast STUN validation but failed "
        "slow validation.", G_STRFUNC);

    g_free (big_buf);
  }

  /* Unhandled STUN; try handling TCP data, then pass to the client. */
  if (message->length > 0  && agent->reliable) {
    if (!nice_socket_is_reliable (nicesock) &&
        !pseudo_tcp_socket_is_closed (component->tcp)) {
      /* If we don’t yet have an underlying selected socket, queue up the
       * incoming data to handle later. This is because we can’t send ACKs (or,
       * more importantly for the first few packets, SYNACKs) without an
       * underlying socket. We’d rather wait a little longer for a pair to be
       * selected, then process the incoming packets and send out ACKs, than try
       * to process them now, fail to send the ACKs, and incur a timeout in our
       * pseudo-TCP state machine. */
      if (component->selected_pair.local == NULL) {
        GOutputVector *vec = g_slice_new (GOutputVector);
        vec->buffer = compact_input_message (message, &vec->size);
        g_queue_push_tail (&component->queued_tcp_packets, vec);
        nice_debug ("%s: Queued %" G_GSSIZE_FORMAT " bytes for agent %p.",
            G_STRFUNC, vec->size, agent);

        return RECV_OOB;
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
    } else if (pseudo_tcp_socket_is_closed (component->tcp)) {
      nice_debug ("Received data on a pseudo tcp FAILED component. Ignoring.");

      retval = RECV_OOB;
      goto done;
    }
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
  gboolean reached_eos = FALSE;
  GError *child_error = NULL;
  NiceInputMessage *messages_orig = NULL;
  guint i;

  g_return_val_if_fail (NICE_IS_AGENT (agent), -1);
  g_return_val_if_fail (stream_id >= 1, -1);
  g_return_val_if_fail (component_id >= 1, -1);
  g_return_val_if_fail (n_messages == 0 || messages != NULL, -1);
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
  if (agent->reliable &&
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
   * if no data was received for an iteration; in which case @child_error will
   * be set to %G_IO_ERROR_WOULD_BLOCK).
   */
  while (!received_enough && !error_reported && !all_sockets_would_block &&
      !reached_eos) {
    NiceInputMessageIter prev_recv_messages_iter;

    g_clear_error (&child_error);
    memcpy (&prev_recv_messages_iter, &component->recv_messages_iter,
        sizeof (NiceInputMessageIter));

    agent_unlock_and_emit (agent);
    g_main_context_iteration (context, blocking);
    agent_lock ();

    if (!agent_find_component (agent, stream_id, component_id,
            &stream, &component)) {
      g_clear_error (&child_error);
      g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE,
          "Component removed during call.");

      component = NULL;
      error_reported = TRUE;

      goto recv_error;
    }

    received_enough =
        nice_input_message_iter_is_at_end (&component->recv_messages_iter,
            component->recv_messages, component->n_recv_messages);
    error_reported = (child_error != NULL &&
        !g_error_matches (child_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK));
    reached_eos = (agent->reliable &&
        pseudo_tcp_socket_is_closed_remotely (component->tcp) &&
        nice_input_message_iter_compare (&prev_recv_messages_iter,
            &component->recv_messages_iter));
    all_sockets_would_block = (!blocking && !reached_eos &&
        nice_input_message_iter_compare (&prev_recv_messages_iter,
            &component->recv_messages_iter));
  }

  n_valid_messages =
      nice_input_message_iter_get_n_valid_messages (
          &component->recv_messages_iter);  /* grab before resetting the iter */

  component_set_io_callback (component, NULL, NULL, NULL, 0, NULL);

recv_error:
  /* Tidy up. Below this point, @component may be %NULL. */
  if (cancellable_source != NULL) {
    g_source_destroy (cancellable_source);
    g_source_unref (cancellable_source);
  }

  g_main_context_unref (context);

  /* Handle errors and cancellations. */
  if (child_error != NULL) {
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
  g_assert (n_valid_messages != 0 || reached_eos);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), -1);
  g_return_val_if_fail (stream_id >= 1, -1);
  g_return_val_if_fail (component_id >= 1, -1);
  g_return_val_if_fail (buf != NULL || buf_len == 0, -1);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), -1);
  g_return_val_if_fail (stream_id >= 1, -1);
  g_return_val_if_fail (component_id >= 1, -1);
  g_return_val_if_fail (buf != NULL || buf_len == 0, -1);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

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
  if (component->selected_pair.local != NULL) {
    if (nice_debug_is_enabled ()) {
      gchar tmpbuf[INET6_ADDRSTRLEN];
      nice_address_to_string (&component->selected_pair.remote->addr, tmpbuf);

      nice_debug ("Agent %p : s%d:%d: sending %u messages to "
          "[%s]:%d", agent, stream_id, component_id, n_messages, tmpbuf,
          nice_address_get_port (&component->selected_pair.remote->addr));
    }

    if(agent->reliable &&
        !nice_socket_is_reliable (component->selected_pair.local->sockptr)) {
      if (!pseudo_tcp_socket_is_closed (component->tcp)) {
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
      } else {
        g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_FAILED,
            "Pseudo-TCP socket not connected.");
      }
    } else {
      NiceSocket *sock;
      NiceAddress *addr;

      sock = component->selected_pair.local->sockptr;
      addr = &component->selected_pair.remote->addr;

      if (nice_socket_is_reliable (sock)) {
        guint i;

        /* ICE-TCP requires that all packets be framed with RFC4571 */
        n_sent = 0;
        for (i = 0; i < n_messages; i++) {
          const NiceOutputMessage *message = &messages[i];
          gsize message_len = output_message_get_size (message);
          gsize offset = 0;
          gsize current_offset = 0;
          gsize offset_in_buffer = 0;
          gint n_sent_framed;
          GOutputVector *local_bufs;
          NiceOutputMessage local_message;
          guint j;
          guint n_bufs = 0;

          /* Count the number of buffers. */
          if (message->n_buffers == -1) {
            for (j = 0; message->buffers[j].buffer != NULL; j++)
              n_bufs++;
          } else {
            n_bufs = message->n_buffers;
          }

          local_bufs = g_malloc_n (n_bufs + 1, sizeof (GOutputVector));
          local_message.buffers = local_bufs;

          while (message_len > 0) {
            guint16 packet_len;
            guint16 rfc4571_frame;

            /* Split long messages into 62KB packets, leaving enough space
             * for TURN overhead as well */
            if (message_len > 0xF800)
              packet_len = 0xF800;
            else
              packet_len = (guint16) message_len;
            message_len -= packet_len;
            rfc4571_frame = htons (packet_len);

            local_bufs[0].buffer = &rfc4571_frame;
            local_bufs[0].size = sizeof (guint16);

            local_message.n_buffers = 1;
            /* If we had to split the message, we need to find which buffer
             * to start copying from and our offset within that buffer */
            offset_in_buffer = 0;
            current_offset = 0;
            for (j = 0; j < n_bufs; j++) {
              if (message->buffers[j].size < offset - current_offset) {
                current_offset += message->buffers[j].size;
                continue;
              } else {
                offset_in_buffer = offset - current_offset;
                current_offset = offset;
                break;
              }
            }

            /* Keep j position in array and start copying from there */
            for (; j < n_bufs; j++) {
              local_bufs[local_message.n_buffers].buffer =
                  ((guint8 *) message->buffers[j].buffer) + offset_in_buffer;
              local_bufs[local_message.n_buffers].size =
                  MIN (message->buffers[j].size, packet_len);
              packet_len -= local_bufs[local_message.n_buffers].size;
              offset += local_bufs[local_message.n_buffers++].size;
              offset_in_buffer = 0;
            }

            /* If we sent part of the message already, then send the rest
             * reliably so the message is sent as a whole even if it's split */
            if (current_offset == 0)
              n_sent_framed = nice_socket_send_messages (sock, addr,
                  &local_message, 1);
            else
              n_sent_framed = nice_socket_send_messages_reliable (sock, addr,
                  &local_message, 1);

            if (component->tcp_writable_cancellable &&
                !nice_socket_can_send (sock, addr))
              g_cancellable_reset (component->tcp_writable_cancellable);

            if (n_sent_framed < 0 && n_sent == 0)
              n_sent = n_sent_framed;
            if (n_sent_framed != 1)
              break;
            /* This is the last split frame, increment n_sent */
            if (message_len == 0)
              n_sent ++;
          }
          g_free (local_bufs);
        }

      } else {
        n_sent = nice_socket_send_messages (sock, addr, messages, n_messages);
      }

      if (n_sent < 0) {
        g_set_error (&child_error, G_IO_ERROR, G_IO_ERROR_FAILED,
            "Error writing data to socket.");
      } else if (n_sent > 0 && allow_partial) {
        g_assert (n_messages == 1);
        n_sent = output_message_get_size (messages);
      }
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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (component_id >= 1, NULL);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (component_id >= 1, NULL);

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

  agent_lock();

  /* step: regenerate tie-breaker value */
  priv_generate_tie_breaker (agent);

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;

    /* step: reset local credentials for the stream and
     * clean up the list of remote candidates */
    stream_restart (agent, stream);
  }

  agent_unlock_and_emit (agent);
  return TRUE;
}

gboolean
nice_agent_restart_stream (
    NiceAgent *agent,
    guint stream_id)
{
  gboolean res = FALSE;
  Stream *stream;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (!stream) {
    g_warning ("Could not find  stream %u", stream_id);
    goto done;
  }

  /* step: reset local credentials for the stream and
   * clean up the list of remote candidates */
  stream_restart (agent, stream);

  res = TRUE;
 done:
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

      stream_close (s);
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

  priv_stop_upnp (agent);

#ifdef HAVE_GUPNP
  if (agent->upnp) {
    g_object_unref (agent->upnp);
    agent->upnp = NULL;
  }
#endif

  g_free (agent->software_attribute);
  agent->software_attribute = NULL;

  if (agent->main_context != NULL)
    g_main_context_unref (agent->main_context);
  agent->main_context = NULL;

  if (G_OBJECT_CLASS (nice_agent_parent_class)->dispose)
    G_OBJECT_CLASS (nice_agent_parent_class)->dispose (object);

}

gboolean
component_io_cb (GSocket *gsocket, GIOCondition condition, gpointer user_data)
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

  /* Remove disconnected sockets when we get a HUP */
  if (condition & G_IO_HUP) {
    nice_debug ("Agent %p: NiceSocket %p has received HUP", agent,
        socket_source->socket);
    if (component->selected_pair.local &&
        component->selected_pair.local->sockptr == socket_source->socket &&
        component->state == NICE_COMPONENT_STATE_READY) {
      nice_debug ("Agent %p: Selected pair socket %p has HUP, declaring failed",
          agent, socket_source->socket);
      agent_signal_component_state_change (agent,
          stream->id, component->id, NICE_COMPONENT_STATE_FAILED);
    }

    component_detach_socket (component, socket_source->socket);
    agent_unlock ();
    return G_SOURCE_REMOVE;
  }

  has_io_callback = component_has_io_callback (component);

  /* Choose which receive buffer to use. If we’re reading for
   * nice_agent_attach_recv(), use a local static buffer. If we’re reading for
   * nice_agent_recv_messages(), use the buffer provided by the client.
   *
   * has_io_callback cannot change throughout this function, as we operate
   * entirely with the agent lock held, and component_set_io_callback() would
   * need to take the agent lock to change the Component’s io_callback. */
  g_assert (!has_io_callback || component->recv_messages == NULL);

  if (agent->reliable && !nice_socket_is_reliable (socket_source->socket)) {
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

    if (pseudo_tcp_socket_is_closed (component->tcp)) {
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
  } else if (has_io_callback) {
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

      if (g_source_is_destroyed (g_main_current_source ())) {
        nice_debug ("Component IO source disappeared during the callback");
        goto out;
      }
      has_io_callback = component_has_io_callback (component);
    }
  } else if (component->recv_messages != NULL) {
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
        g_clear_error (component->recv_buf_error);
      } else if (retval == RECV_WOULD_BLOCK) {
        /* EWOULDBLOCK. */
        if (component->recv_messages_iter.message == 0 &&
            component->recv_buf_error != NULL &&
            *component->recv_buf_error == NULL) {
          g_set_error_literal (component->recv_buf_error, G_IO_ERROR,
              G_IO_ERROR_WOULD_BLOCK, g_strerror (EAGAIN));
        }
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

out:
  g_object_unref (agent);
  agent_unlock_and_emit (agent);
  return G_SOURCE_REMOVE;
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

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);
  g_return_val_if_fail (component_id >= 1, FALSE);

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
    if (agent->reliable && !pseudo_tcp_socket_is_closed (component->tcp) &&
        component->tcp_readable)
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

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);
  g_return_val_if_fail (component_id >= 1, FALSE);
  g_return_val_if_fail (lfoundation, FALSE);
  g_return_val_if_fail (rfoundation, FALSE);

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

  if (agent->reliable && !nice_socket_is_reliable (pair.local->sockptr) &&
      pseudo_tcp_socket_is_closed (component->tcp)) {
    nice_debug ("Agent %p: not setting selected pair for s%d:%d because "
        "pseudo tcp socket does not exist in reliable mode", agent,
        stream->id, component->id);
    goto done;
  }

  /* step: change component state */
  agent_signal_component_state_change (agent, stream_id, component_id, NICE_COMPONENT_STATE_READY);

  /* step: set the selected pair */
  component_update_selected_pair (component, &pair);
  agent_signal_new_selected_pair (agent, stream_id, component_id,
      pair.local, pair.remote);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);
  g_return_val_if_fail (component_id >= 1, FALSE);
  g_return_val_if_fail (local != NULL, FALSE);
  g_return_val_if_fail (remote != NULL, FALSE);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (component_id >= 1, NULL);

  agent_lock();

  /* Reliable streams are pseudotcp or MUST use RFC 4571 framing */
  if (agent->reliable)
    goto done;

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    goto done;

  if (!component->selected_pair.local || !component->selected_pair.remote)
    goto done;

  if (component->selected_pair.local->type == NICE_CANDIDATE_TYPE_RELAYED)
    goto done;

  /* ICE-TCP requires RFC4571 framing, even if unreliable */
  if (component->selected_pair.local->transport != NICE_CANDIDATE_TRANSPORT_UDP)
    goto done;

  nice_socket = (NiceSocket *)component->selected_pair.local->sockptr;
  if (nice_socket->fileno)
    g_socket = g_object_ref (nice_socket->fileno);

 done:
  agent_unlock_and_emit (agent);

  return g_socket;
}

/* Create a new timer GSource with the given @name, @interval, callback
 * @function and @data, and assign it to @out, destroying and freeing any
 * existing #GSource in @out first.
 *
 * This guarantees that a timer won’t be overwritten without being destroyed.
 */
void agent_timeout_add_with_context (NiceAgent *agent, GSource **out,
    const gchar *name, guint interval, GSourceFunc function, gpointer data)
{
  GSource *source;

  g_return_if_fail (function != NULL);
  g_return_if_fail (out != NULL);

  /* Destroy any existing source. */
  if (*out != NULL) {
    g_source_destroy (*out);
    g_source_unref (*out);
    *out = NULL;
  }

  /* Create the new source. */
  source = g_timeout_source_new (interval);

  g_source_set_name (source, name);
  g_source_set_callback (source, function, data, NULL);
  g_source_attach (source, agent->main_context);

  /* Return it! */
  *out = source;
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
  NiceCandidate *local = NULL, *remote = NULL;
  guint64 priority;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id != 0, FALSE);
  g_return_val_if_fail (component_id != 0, FALSE);
  g_return_val_if_fail (candidate != NULL, FALSE);

  agent_lock();

  /* step: check if the component exists*/
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream);

  /* Store previous selected pair */
  local = component->selected_pair.local;
  remote = component->selected_pair.remote;
  priority = component->selected_pair.priority;

  /* step: set the selected pair */
  lcandidate = component_set_selected_remote_candidate (agent, component,
      candidate);
  if (!lcandidate)
    goto done;

  if (agent->reliable && !nice_socket_is_reliable (lcandidate->sockptr) &&
      pseudo_tcp_socket_is_closed (component->tcp)) {
    nice_debug ("Agent %p: not setting selected remote candidate s%d:%d because"
        " pseudo tcp socket does not exist in reliable mode", agent,
        stream->id, component->id);
    /* Revert back to previous selected pair */
    /* FIXME: by doing this, we lose the keepalive tick */
    component->selected_pair.local = local;
    component->selected_pair.remote = remote;
    component->selected_pair.priority = priority;
    goto done;
  }

  /* step: change component state */
  agent_signal_component_state_change (agent, stream_id, component_id, NICE_COMPONENT_STATE_READY);

  agent_signal_new_selected_pair (agent, stream_id, component_id,
      lcandidate, candidate);

  ret = TRUE;

 done:
  agent_unlock_and_emit (agent);
  return ret;
}

void
_priv_set_socket_tos (NiceAgent *agent, NiceSocket *sock, gint tos)
{
  if (sock->fileno == NULL)
    return;

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

  g_return_if_fail (NICE_IS_AGENT (agent));
  g_return_if_fail (stream_id >= 1);

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
  g_return_if_fail (NICE_IS_AGENT (agent));

  agent_lock();

  g_free (agent->software_attribute);
  if (software)
    agent->software_attribute = g_strdup_printf ("%s/%s",
        software, PACKAGE_STRING);

  nice_agent_reset_all_stun_agents (agent, TRUE);

  agent_unlock_and_emit (agent);
}

NICEAPI_EXPORT gboolean
nice_agent_set_stream_name (NiceAgent *agent, guint stream_id,
    const gchar *name)
{
  Stream *stream_to_name = NULL;
  GSList *i;
  gboolean ret = FALSE;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);
  g_return_val_if_fail (name, FALSE);

  if (strcmp (name, "audio") &&
      strcmp (name, "video") &&
      strcmp (name, "text") &&
      strcmp (name, "application") &&
      strcmp (name, "message") &&
      strcmp (name, "image")) {
    g_critical ("Stream name %s will produce invalid SDP, only \"audio\","
        " \"video\", \"text\", \"application\", \"image\" and \"message\""
        " are valid", name);
  }

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (component_id >= 1, NULL);

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

static const gchar *
_transport_to_sdp (NiceCandidateTransport type) {
  switch(type) {
    case NICE_CANDIDATE_TRANSPORT_UDP:
      return "UDP";
    case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
    case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
    case NICE_CANDIDATE_TRANSPORT_TCP_SO:
      return "TCP";
    default:
      return "???";
  }
}

static const gchar *
_transport_to_sdp_tcptype (NiceCandidateTransport type) {
  switch(type) {
    case NICE_CANDIDATE_TRANSPORT_UDP:
      return "";
    case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
      return "active";
    case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
      return "passive";
    case NICE_CANDIDATE_TRANSPORT_TCP_SO:
      return "so";
    default:
      return "";
  }
}

static void
_generate_candidate_sdp (NiceAgent *agent,
    NiceCandidate *candidate, GString *sdp)
{
  gchar ip4[INET6_ADDRSTRLEN];
  guint16 port;

  nice_address_to_string (&candidate->addr, ip4);
  port = nice_address_get_port (&candidate->addr);
  g_string_append_printf (sdp, "a=candidate:%.*s %d %s %d %s %d",
      NICE_CANDIDATE_MAX_FOUNDATION, candidate->foundation,
      candidate->component_id,
      _transport_to_sdp (candidate->transport),
      candidate->priority, ip4, port == 0 ? 9 : port);
  g_string_append_printf (sdp, " typ %s", _cand_type_to_sdp (candidate->type));
  if (nice_address_is_valid (&candidate->base_addr) &&
      !nice_address_equal (&candidate->addr, &candidate->base_addr)) {
    port = nice_address_get_port (&candidate->addr);
    nice_address_to_string (&candidate->base_addr, ip4);
    g_string_append_printf (sdp, " raddr %s rport %d", ip4,
        port == 0 ? 9 : port);
  }
  if (candidate->transport != NICE_CANDIDATE_TRANSPORT_UDP) {
    g_string_append_printf (sdp, " tcptype %s",
        _transport_to_sdp_tcptype (candidate->transport));
  }
}

static void
_generate_stream_sdp (NiceAgent *agent, Stream *stream,
    GString *sdp, gboolean include_non_ice)
{
  GSList *i, *j;

  if (include_non_ice) {
    NiceAddress rtp, rtcp;
    gchar ip4[INET6_ADDRSTRLEN] = "";

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);

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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (candidate != NULL, NULL);

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
  GSList *l, *stream_item = NULL;
  gint i;
  gint ret = 0;

  g_return_val_if_fail (NICE_IS_AGENT (agent), -1);
  g_return_val_if_fail (sdp != NULL, -1);

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
      if (stream_item == NULL)
        stream_item = agent->streams;
      else
        stream_item = stream_item->next;
      if (!stream_item) {
        g_critical("More streams in SDP than in agent");
        ret = -1;
        goto done;
      }
      current_stream = stream_item->data;
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

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (sdp != NULL, NULL);

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
  guint component_id = 0;
  const gchar *transport = NULL;
  guint32 priority = 0;
  const gchar *addr = NULL;
  guint16 port = 0;
  const gchar *type = NULL;
  const gchar *tcptype = NULL;
  const gchar *raddr = NULL;
  guint16 rport = 0;
  static const gchar *type_names[] = {"host", "srflx", "prflx", "relay"};
  NiceCandidateTransport ctransport;
  guint i;

  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (sdp != NULL, NULL);

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
        } else if (g_strcmp0 (tokens[i], "tcptype") == 0) {
          tcptype = tokens[i + 1];
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

  if (g_ascii_strcasecmp (transport, "UDP") == 0)
    ctransport = NICE_CANDIDATE_TRANSPORT_UDP;
  else if (g_ascii_strcasecmp (transport, "TCP-SO") == 0)
    ctransport = NICE_CANDIDATE_TRANSPORT_TCP_SO;
  else if (g_ascii_strcasecmp (transport, "TCP-ACT") == 0)
    ctransport = NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
  else if (g_ascii_strcasecmp (transport, "TCP-PASS") == 0)
    ctransport = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
  else if (g_ascii_strcasecmp (transport, "TCP") == 0) {
    if (g_ascii_strcasecmp (tcptype, "so") == 0)
      ctransport = NICE_CANDIDATE_TRANSPORT_TCP_SO;
    else if (g_ascii_strcasecmp (tcptype, "active") == 0)
      ctransport = NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
    else if (g_ascii_strcasecmp (tcptype, "passive") == 0)
      ctransport = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
    else
      goto done;
  } else
    goto done;

  candidate = nice_candidate_new(ntype);
  candidate->component_id = component_id;
  candidate->stream_id = stream_id;
  candidate->transport = ctransport;
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

NICEAPI_EXPORT gboolean
nice_agent_forget_relays (NiceAgent *agent, guint stream_id, guint component_id)
{
  Component *component;
  gboolean ret = TRUE;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);
  g_return_val_if_fail (component_id >= 1, FALSE);

  agent_lock ();

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    ret = FALSE;
    goto done;
  }

  component_clean_turn_servers (component);

 done:
  agent_unlock_and_emit (agent);

  return ret;
}

/* Helper function to allow us to send connchecks reliably.
 * If the transport is reliable, then we request a reliable send, which will
 * either send the data, or queue it in the case of unestablished http/socks5
 * proxies or tcp-turn. If the transport is not reliable, then it could be an
 * unreliable tcp-bsd, so we still try a reliable send to see if it can succeed
 * meaning the message was queued, or if it failed, then it was either udp-bsd
 * or turn and so we retry with a non reliable send and let the retransmissions
 * take care of the rest.
 * This is in order to avoid having to retransmit something if the underlying
 * socket layer can queue the message and send it once a connection is
 * established.
 */
gssize
agent_socket_send (NiceSocket *sock, const NiceAddress *addr, gsize len,
    const gchar *buf)
{
  if (nice_socket_is_reliable (sock)) {
    guint16 rfc4571_frame = htons (len);
    GOutputVector local_buf[2] = {{&rfc4571_frame, 2}, { buf, len }};
    NiceOutputMessage local_message = { local_buf, 2};
    gint ret;

    /* ICE-TCP requires that all packets be framed with RFC4571 */
    ret = nice_socket_send_messages_reliable (sock, addr, &local_message, 1);
    if (ret == 1)
      return len;
    return ret;
  } else {
    gssize ret = nice_socket_send_reliable (sock, addr, len, buf);
    if (ret < 0)
      ret = nice_socket_send (sock, addr, len, buf);
    return ret;
  }
}

NiceComponentState
nice_agent_get_component_state (NiceAgent *agent,
    guint stream_id, guint component_id)
{
  NiceComponentState state = NICE_COMPONENT_STATE_FAILED;
  Component *component;

  agent_lock ();

  if (agent_find_component (agent, stream_id, component_id, NULL, &component))
    state = component->state;

  agent_unlock ();

  return state;
}
