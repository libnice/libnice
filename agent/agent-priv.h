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

#ifndef _NICE_AGENT_PRIV_H
#define _NICE_AGENT_PRIV_H

/* note: this is a private header part of agent.h */

#include <glib.h>

#include "agent.h"
#include "component.h"
#include "candidate.h"
#include "stream.h"
#include "conncheck.h"

#define NICE_AGENT_TIMER_TA_DEFAULT 20      /* timer Ta, msecs (impl. defined) */
#define NICE_AGENT_TIMER_TR_DEFAULT 15000   /* timer Tr, msecs (ICE ID-17) */

/** An upper limit to size of STUN packets handled (based on Ethernet
 * MTU and estimated typical sizes of ICE STUN packet */
#define MAX_STUN_DATAGRAM_PAYLOAD    1300

struct _NiceAgent
{
  GObject parent;                 /**< gobject pointer */

  gboolean full_mode;             /**< property: full-mode */
  NiceUDPSocketFactory *socket_factory; /**< property: socket factory */
  GTimeVal next_check_tv;         /**< property: next conncheck timestamp */
  gchar *stun_server_ip;          /**< property: STUN server IP */
  guint stun_server_port;         /**< property: STUN server port */
  gchar *turn_server_ip;          /**< property: TURN server IP */
  guint turn_server_port;         /**< property: TURN server port */
  gboolean controlling_mode;      /**< property: controlling-mode */
  guint timer_ta;                 /**< property: timer Ta */

  GSList *local_addresses;        /**< list of NiceAddresses for local
				     interfaces */
  GSList *streams;                /**< list of Stream objects */
  gboolean main_context_set;      /**< is the main context set */
  GMainContext *main_context;     /**< main context pointer */
  NiceAgentRecvFunc read_func;    /**< callback for media deliver */
  gpointer read_func_data;        /**< media delivery callback context */
  guint next_candidate_id;        /**< id of next created candidate */
  guint next_stream_id;           /**< id of next created candidate */
  NiceRNG *rng;                   /**< random number generator */
  GSList *discovery_list;         /**< list of CandidateDiscovery items */
  guint discovery_unsched_items;  /**< number of discovery items unscheduled */
  guint discovery_timer_id;       /**< id of discovery timer */
  GSList *conncheck_list;         /**< list of CandidatePair items */
  guint conncheck_timer_id;       /**< id of discovery timer */
  NiceCheckListState conncheck_state; /**< checklist state */
  guint keepalive_timer_id;       /**< id of keepalive timer */
  guint64 tie_breaker;            /**< tie breaker (ICE sect 5.2
				     "Determining Role" ID-17) */
  gchar ufragtmp[NICE_STREAM_MAX_UNAME]; /**< preallocated buffer for uname processing */ 
  /* XXX: add pointer to internal data struct for ABI-safe extensions */
};

gboolean
agent_find_component (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  Stream **stream,
  Component **component);

Stream *agent_find_stream (NiceAgent *agent, guint stream_id);

void agent_signal_gathering_done (NiceAgent *agent);

void agent_signal_new_selected_pair (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const gchar *local_foundation,
  const gchar *remote_foundation);

void agent_signal_component_state_change (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceComponentState state);

void agent_signal_new_candidate (
  NiceAgent *agent,
  NiceCandidate *candidate);

void agent_signal_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate);

void agent_signal_initial_binding_request_received (NiceAgent *agent, Stream *stream);

void agent_free_discovery_candidate_udp (gpointer data, gpointer user_data);

#endif /*_NICE_AGENT_PRIV_H */
