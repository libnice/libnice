/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
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

/*
 * @file component.c
 * @brief ICE component functions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include "debug.h"

#include "component.h"
#include "agent-priv.h"

Component *
component_new (guint id)
{
  Component *component;

  component = g_slice_new0 (Component);
  component->id = id;
  component->state = NICE_COMPONENT_STATE_DISCONNECTED;
  component->restart_candidate = NULL;
  component->tcp = NULL;

  return component;
}


void
component_free (Component *cmp)
{
  GSList *i;
  GList *item;

  for (i = cmp->local_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    nice_candidate_free (candidate);
  }

  for (i = cmp->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    nice_candidate_free (candidate);
  }

  if (cmp->restart_candidate)
    nice_candidate_free (cmp->restart_candidate),
      cmp->restart_candidate = NULL;

  for (i = cmp->sockets; i; i = i->next) {
    NiceSocket *udpsocket = i->data;
    nice_socket_free (udpsocket);
  }

  for (i = cmp->gsources; i; i = i->next) {
    GSource *source = i->data;
    g_source_destroy (source);
    g_source_unref (source);
  }
 
  for (i = cmp->incoming_checks; i; i = i->next) {
    IncomingCheck *icheck = i->data;
    g_free (icheck->username);
    g_slice_free (IncomingCheck, icheck);
  }

  g_slist_free (cmp->local_candidates);
  g_slist_free (cmp->remote_candidates);
  g_slist_free (cmp->sockets);
  g_slist_free (cmp->gsources);
  g_slist_free (cmp->incoming_checks);

  for (item = cmp->turn_servers; item; item = g_list_next (item)) {
    TurnServer *turn = item->data;
    g_free (turn->username);
    g_free (turn->password);
    g_slice_free (TurnServer, turn);
  }
  g_list_free (cmp->turn_servers);

  if (cmp->selected_pair.keepalive.tick_source != NULL) {
    g_source_destroy (cmp->selected_pair.keepalive.tick_source);
    g_source_unref (cmp->selected_pair.keepalive.tick_source);
    cmp->selected_pair.keepalive.tick_source = NULL;
  }

  if (cmp->tcp_clock) {
    g_source_destroy (cmp->tcp_clock);
    g_source_unref (cmp->tcp_clock);
    cmp->tcp_clock = NULL;
  }
  if (cmp->tcp) {
    pseudo_tcp_socket_close (cmp->tcp, TRUE);
    g_object_unref (cmp->tcp);
    cmp->tcp = NULL;
  }
  if (cmp->tcp_data != NULL) {
    g_slice_free (TcpUserData, cmp->tcp_data);
    cmp->tcp_data = NULL;
  }

  if (cmp->ctx != NULL) {
    g_main_context_unref (cmp->ctx);
    cmp->ctx = NULL;
  }

  g_slice_free (Component, cmp);
}

/*
 * Finds a candidate pair that has matching foundation ids.
 *
 * @return TRUE if pair found, pointer to pair stored at 'pair'
 */
gboolean
component_find_pair (Component *cmp, NiceAgent *agent, const gchar *lfoundation, const gchar *rfoundation, CandidatePair *pair)
{
  GSList *i;
  CandidatePair result;

  memset (&result, 0, sizeof(result));

  for (i = cmp->local_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    if (strncmp (candidate->foundation, lfoundation, NICE_CANDIDATE_MAX_FOUNDATION) == 0) {
      result.local = candidate;
      break;
    }
  }

  for (i = cmp->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    if (strncmp (candidate->foundation, rfoundation, NICE_CANDIDATE_MAX_FOUNDATION) == 0) {
      result.remote = candidate;
      break;
    }
  }

  if (result.local && result.remote) {
    result.priority = agent_candidate_pair_priority (agent, result.local, result.remote);
    if (pair)
      *pair = result;
    return TRUE;
  }

  return FALSE;
}

/*
 * Resets the component state to that of a ICE restarted
 * session.
 */
gboolean
component_restart (Component *cmp)
{
  GSList *i;

  for (i = cmp->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;

    /* note: do not remove the remote candidate that is
     *       currently part of the 'selected pair', see ICE
     *       9.1.1.1. "ICE Restarts" (ID-19) */
    if (candidate == cmp->selected_pair.remote) {
      if (cmp->restart_candidate)
	nice_candidate_free (cmp->restart_candidate);
      cmp->restart_candidate = candidate;
    }
    else 
      nice_candidate_free (candidate);
  }
  g_slist_free (cmp->remote_candidates),
    cmp->remote_candidates = NULL;

  for (i = cmp->incoming_checks; i; i = i->next) {
    IncomingCheck *icheck = i->data;
    g_free (icheck->username);
    g_slice_free (IncomingCheck, icheck);
  }
  g_slist_free (cmp->incoming_checks);
  cmp->incoming_checks = NULL;

  /* note: component state managed by agent */

  return TRUE;
}

/*
 * Changes the selected pair for the component to 'pair'. Does not
 * emit the "selected-pair-changed" signal.
 */ 
void component_update_selected_pair (Component *component, const CandidatePair *pair)
{
  g_assert (component);
  g_assert (pair);
  nice_debug ("setting SELECTED PAIR for component %u: %s:%s (prio:%"
      G_GUINT64_FORMAT ").", component->id, pair->local->foundation,
      pair->remote->foundation, pair->priority);

  if (component->selected_pair.keepalive.tick_source != NULL) {
    g_source_destroy (component->selected_pair.keepalive.tick_source);
    g_source_unref (component->selected_pair.keepalive.tick_source);
    component->selected_pair.keepalive.tick_source = NULL;
  }

  memset (&component->selected_pair, 0, sizeof(CandidatePair));

  component->selected_pair.local = pair->local;
  component->selected_pair.remote = pair->remote;
  component->selected_pair.priority = pair->priority;

}

/*
 * Finds a remote candidate with matching address and 
 * transport.
 *
 * @return pointer to candidate or NULL if not found
 */
NiceCandidate *
component_find_remote_candidate (const Component *component, const NiceAddress *addr, NiceCandidateTransport transport)
{
  GSList *i;

  for (i = component->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;

    if (nice_address_equal(&candidate->addr, addr) &&
	candidate->transport == transport)
      return candidate;

  }
  
  return NULL;
}

/*
 * Sets the desired remote candidate as the selected pair
 *
 * It will start sending on the highest priority pair available with
 * this candidate.
 */

NiceCandidate *
component_set_selected_remote_candidate (NiceAgent *agent, Component *component,
    NiceCandidate *candidate)
{
  NiceCandidate *local = NULL;
  NiceCandidate *remote = NULL;
  guint64 priority = 0;
  GSList *item = NULL;

  for (item = component->local_candidates; item; item = g_slist_next (item)) {
    NiceCandidate *tmp = item->data;
    guint64 tmp_prio = 0;

    if (tmp->transport != candidate->transport ||
	tmp->addr.s.addr.sa_family != candidate->addr.s.addr.sa_family ||
        tmp->type != NICE_CANDIDATE_TYPE_HOST)
      continue;

    tmp_prio = agent_candidate_pair_priority (agent, tmp, candidate);

    if (tmp_prio > priority) {
      priority = tmp_prio;
      local = tmp;
    }
  }

  if (local == NULL)
    return NULL;

  remote = component_find_remote_candidate (component, &candidate->addr,
      candidate->transport);

  if (!remote) {
    remote = nice_candidate_copy (candidate);
    component->remote_candidates = g_slist_append (component->remote_candidates,
        remote);
    agent_signal_new_remote_candidate (agent, remote);
  }

  if (component->selected_pair.keepalive.tick_source != NULL) {
    g_source_destroy (component->selected_pair.keepalive.tick_source);
    g_source_unref (component->selected_pair.keepalive.tick_source);
    component->selected_pair.keepalive.tick_source = NULL;
  }

  memset (&component->selected_pair, 0, sizeof(CandidatePair));
  component->selected_pair.local = local;
  component->selected_pair.remote = remote;
  component->selected_pair.priority = priority;

  return local;
}
