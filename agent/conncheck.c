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
 *   Kai Vehmanen, Nokia
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

/**
 * @file conncheck.c
 * @brief ICE connectivity checks
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <string.h>

#include <glib.h>

#include "agent.h"
#include "agent-priv.h"
#include "conncheck.h"
#include "discovery.h"

static void priv_update_check_list_failed_components (NiceAgent *agent, Stream *stream);
static void priv_prune_pending_checks (Stream *stream, guint component_id);
static gboolean priv_schedule_triggered_check (NiceAgent *agent, Stream *stream, Component *component, NiceUDPSocket *local_socket, NiceCandidate *remote_cand, gboolean use_candidate);
static void priv_mark_pair_nominated (NiceAgent *agent, Stream *stream, Component *component, NiceCandidate *remotecand);

static inline int priv_timer_expired (GTimeVal *restrict timer, GTimeVal *restrict now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

/**
 * Finds the next connectivity check in WAITING state.
 */
static CandidateCheckPair *priv_conn_check_find_next_waiting (GSList *conn_check_list)
{
  GSList *i;

  /* note: list is sorted in priority order to first waiting check has
   *       the highest priority */

  for (i = conn_check_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->state == NICE_CHECK_WAITING)
      return p;
  }

  return NULL;
}

/**
 * Initiates a new connectivity check for a ICE candidate pair.
 *
 * @return TRUE on success, FALSE on error
 */
static gboolean priv_conn_check_initiate (NiceAgent *agent, CandidateCheckPair *pair)
{
  /* XXX: from ID-16 onwards, the checks should not be sent
   * immediately, but be put into the "triggered queue",
   * see  "7.2.1.4 Triggered Checks"
   */
  g_get_current_time (&pair->next_tick);
  g_time_val_add (&pair->next_tick, agent->timer_ta * 1000);
  pair->state = NICE_CHECK_IN_PROGRESS;
  conn_check_send (agent, pair);
  return TRUE;
}

/**
 * Unfreezes the next connectivity check in the list. Follows the
 * algorithm (2.) defined in 5.7.4 (Computing States) of the ICE spec
 * (ID-19), with some exceptions (see comments in code).
 *
 * See also sect 7.1.2.2.3 (Updating Pair States), and
 * priv_conn_check_unfreeze_related().
 * 
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static gboolean priv_conn_check_unfreeze_next (NiceAgent *agent)
{
  CandidateCheckPair *pair = NULL;
  GSList *i, *j;

  /* XXX: the unfreezing is implemented a bit differently than in the
   *      current ICE spec, but should still be interoperate:
   *   - checks are not grouped by foundation
   *   - one frozen check is unfrozen (lowest component-id, highest
   *     priority)
   */

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    guint64 max_frozen_priority = 0;

    for (j = stream->conncheck_list; j ; j = j->next) {
      CandidateCheckPair *p = j->data;

      /* XXX: the prio check could be removed as the pairs are sorted
       *       already */

      if (p->state == NICE_CHECK_FROZEN) {
	if (p->priority > max_frozen_priority) {
	  max_frozen_priority = p->priority;
	  pair = p;
	}
      }
    }

    if (pair) 
      break;
  }
  
  if (pair) {
    g_debug ("Agent %p : Pair %p with s/c-id %u/%u (%s) unfrozen.", agent, pair, pair->stream_id, pair->component_id, pair->foundation);
    pair->state = NICE_CHECK_WAITING;
    return TRUE;
  }

  return FALSE;
}

/**
 * Unfreezes the next next connectivity check in the list after
 * check 'success_check' has succesfully completed.
 *
 * See sect 7.1.2.2.3 (Updating Pair States) of ICE spec (ID-19).
 * 
 * @param agent context
 * @param ok_check a connectivity check that has just completed
 *
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static void priv_conn_check_unfreeze_related (NiceAgent *agent, Stream *stream, CandidateCheckPair *ok_check)
{
  GSList *i, *j;
  guint unfrozen = 0;

  g_assert (ok_check);
  g_assert (ok_check->state == NICE_CHECK_SUCCEEDED);
  g_assert (stream);
  g_assert (stream->id == ok_check->stream_id);

  /* step: perform the step (1) of 'Updating Pair States' */
  for (i = stream->conncheck_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;
   
    if (p->stream_id == ok_check->stream_id) {
      if (p->state == NICE_CHECK_FROZEN &&
	  strcmp (p->foundation, ok_check->foundation) == 0) {
	g_debug ("Agent %p : Unfreezing check %p (after succesful check %p).", agent, p, ok_check);
	p->state = NICE_CHECK_WAITING;
	++unfrozen;
      }
    }
  }

  /* step: perform the step (2) of 'Updating Pair States' */
  stream = agent_find_stream (agent, ok_check->stream_id);
  if (stream_all_components_ready (stream)) {
    /* step: unfreeze checks from other streams */
    for (i = agent->streams; i ; i = i->next) {
      Stream *s = i->data;
      for (j = stream->conncheck_list; j ; j = j->next) {
	CandidateCheckPair *p = j->data;

	if (p->stream_id == s->id &&
	    p->stream_id != ok_check->stream_id) {
	  if (p->state == NICE_CHECK_FROZEN &&
	      strcmp (p->foundation, ok_check->foundation) == 0) {
	    g_debug ("Agent %p : Unfreezing check %p from stream %u (after succesful check %p).", agent, p, s->id, ok_check);
	    p->state = NICE_CHECK_WAITING;
	    ++unfrozen;
					    
	  }
	}
      }
      /* note: only unfreeze check from one stream at a time */
      if (unfrozen)
	break;
    }
  }    

  if (unfrozen == 0) 
    priv_conn_check_unfreeze_next (agent);
}

/**
 * Helper function for connectivity check timer callback that
 * runs through the stream specific part of the state machine. 
 *
 * @param schedule if TRUE, schedule a new check
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_conn_check_tick_stream (Stream *stream, NiceAgent *agent, GTimeVal *now)
{
  gboolean keep_timer_going = FALSE;
  guint s_inprogress = 0, s_succeeded = 0, s_nominated = 0, s_waiting_for_nomination = 0;
  guint frozen = 0, waiting = 0;
  GSList *i, *k;

  for (i = stream->conncheck_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;
      
    if (p->state == NICE_CHECK_IN_PROGRESS) {
      if (p->stun_ctx == NULL) {
	g_debug ("Agent %p : STUN connectivity check was cancelled, marking as done.", agent);
	p->state = NICE_CHECK_FAILED;
      }
      else if (priv_timer_expired (&p->next_tick, now)) {
	int res = stun_bind_elapse (p->stun_ctx);
	if (res == EAGAIN) {
	  /* case: not ready, so schedule a new timeout */
	  unsigned int timeout = stun_bind_timeout (p->stun_ctx);
	  
	  /* note: convert from milli to microseconds for g_time_val_add() */
	  p->next_tick = *now;
	  g_time_val_add (&p->next_tick, timeout * 1000);
	  
	  keep_timer_going = TRUE;
	  p->traffic_after_tick = TRUE; /* for keepalive timer */
	}
	else {
	  /* case: error, abort processing */
	  g_debug ("Agent %p : Retransmissions failed, giving up on connectivity check %p", agent, p);
	  p->state = NICE_CHECK_FAILED;
	  p->stun_ctx = NULL;
	}
      }
    }
    
    if (p->state == NICE_CHECK_FROZEN)
      ++frozen;
    else if (p->state == NICE_CHECK_IN_PROGRESS)
      ++s_inprogress;
    else if (p->state == NICE_CHECK_WAITING)
      ++waiting;
    else if (p->state == NICE_CHECK_SUCCEEDED)
      ++s_succeeded;
    
    if (p->state == NICE_CHECK_SUCCEEDED && p->nominated)
      ++s_nominated;
    else if (p->state == NICE_CHECK_SUCCEEDED && !p->nominated)
      ++s_waiting_for_nomination;
    }
    
    /* note: keep the timer going as long as there is work to be done */
  if (s_inprogress)
    keep_timer_going = TRUE;
  
    /* note: if some components have established connectivity,
     *       but yet no nominated pair, keep timer going */
  if (s_nominated < stream->n_components &&
      s_waiting_for_nomination) {
    keep_timer_going = TRUE;
    if (agent->controlling_mode) {
      guint n;
      for (n = 0; n < stream->n_components; n++) {
	for (k = stream->conncheck_list; k ; k = k->next) {
	  CandidateCheckPair *p = k->data;
	  /* note: highest priority item selected (list always sorted) */
	  if (p->state == NICE_CHECK_SUCCEEDED ||
	      p->state == NICE_CHECK_DISCOVERED) {
	    g_debug ("Agent %p : restarting check %p as the nominated pair.", agent, p);
	    p->nominated = TRUE;
	    priv_conn_check_initiate (agent, p);	
	    break; /* move to the next component */
	  }
	}
      }
    }
  }
  
#ifndef NDEBUG
  {
    static int tick_counter = 0;
    if (tick_counter++ % 50 == 0 || keep_timer_going != TRUE)
      g_debug ("Agent %p : timer(%p) tick #%u: %u frozen, %u in-progress, %u waiting, %u succeeded, %u nominated, %u waiting-for-nom.", agent, 
	       agent, tick_counter, frozen, s_inprogress, waiting, s_succeeded, s_nominated, s_waiting_for_nomination);
  }
#endif

  return keep_timer_going;

}


/**
 * Timer callback that handles initiating and managing connectivity
 * checks (paced by the Ta timer).
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_conn_check_tick_unlocked (gpointer pointer)
{
  CandidateCheckPair *pair = NULL;
  NiceAgent *agent = pointer;
  gboolean keep_timer_going = FALSE;
  GSList *i, *j;
  GTimeVal now;

  /* step: process ongoing STUN transactions */
  g_get_current_time (&now);

  /* step: find the highest priority waiting check and send it */
  for (i = agent->streams; i ; i = i->next) {
    Stream *stream = i->data;
  
    pair = priv_conn_check_find_next_waiting (stream->conncheck_list);  

    if (pair)
      break;
  }

  if (pair) {
    priv_conn_check_initiate (agent, pair);
    keep_timer_going = TRUE;
  }
  else 
    priv_conn_check_unfreeze_next (agent);

  for (j = agent->streams; j; j = j->next) {
    Stream *stream = j->data;
    gboolean res =
      priv_conn_check_tick_stream (stream, agent, &now);
    if (res)
      keep_timer_going = res;
  }
  
  /* step: stop timer if no work left */
  if (keep_timer_going != TRUE) {
    g_debug ("Agent %p : %s: stopping conncheck timer", agent, G_STRFUNC);
    for (i = agent->streams; i; i = i->next) {
      Stream *stream = i->data;
      priv_update_check_list_failed_components (agent, stream);
      stream->conncheck_state = NICE_CHECKLIST_COMPLETED;
    }
    conn_check_free (agent);
    /* XXX: what to signal, is all processing now really done? */
    g_debug ("Agent %p : changing conncheck state to COMPLETED.", agent);
  }

  return keep_timer_going;
}

static gboolean priv_conn_check_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  gboolean ret;

  g_mutex_lock (agent->mutex);
  ret = priv_conn_check_tick_unlocked (pointer);
  g_mutex_unlock (agent->mutex);

  return ret;
}

/**
 * Timer callback that handles initiating and managing connectivity
 * checks (paced by the Ta timer).
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_conn_keepalive_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  GSList *i, *j;
  int errors = 0;
  gboolean ret = FALSE;

  g_mutex_lock (agent->mutex);

  /* case 1: session established and media flowing
   *         (ref ICE sect 10 "Keepalives" ID-19)  */
  for (i = agent->streams; i; i = i->next) {

    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *component = j->data;
      if (component->selected_pair.local != NULL &&
	  component->media_after_tick != TRUE) {
	CandidatePair *p = &component->selected_pair;
	struct sockaddr sockaddr;
	int res;

	memset (&sockaddr, 0, sizeof (sockaddr));
	nice_address_copy_to_sockaddr (&p->remote->addr, &sockaddr);

	res = stun_bind_keepalive (p->local->sockptr->fileno,
				   &sockaddr, sizeof (sockaddr));
	g_debug ("Agent %p : stun_bind_keepalive for pair %p res %d (%s).", agent, p, res, strerror (res));
	if (res < 0)
	  ++errors;
      }
      component->media_after_tick = FALSE;
    }
  }

  /* case 2: connectivity establishment ongoing
   *         (ref ICE sect 4.1.1.4 "Keeping Candidates Alive" ID-19)  */
  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    if (stream->conncheck_state == NICE_CHECKLIST_RUNNING) {
      for (j = stream->conncheck_list; j ; j = j->next) {
	CandidateCheckPair *p = j->data;

	if (p->traffic_after_tick != TRUE) {
	  g_debug ("Agent %p : resending STUN-CC to keep the candidate alive (pair %p).", agent, p);
	  conn_check_send (agent, p);
	}
	p->traffic_after_tick = FALSE;
      }
    }
  }

  if (errors) {
    g_debug ("Agent %p : %s: stopping keepalive timer", agent, G_STRFUNC);
    goto done;
  }

  ret = TRUE;

 done:
  g_mutex_unlock (agent->mutex);
  return ret;
}

/**
 * Initiates the next pending connectivity check.
 * 
 * @return TRUE if a pending check was scheduled
 */
gboolean conn_check_schedule_next (NiceAgent *agent)
{
  gboolean res = priv_conn_check_unfreeze_next (agent);
  g_debug ("Agent %p : priv_conn_check_unfreeze_next returned %d", agent, res);

  if (agent->discovery_unsched_items > 0)
    g_debug ("Agent %p : WARN: starting conn checks before local candidate gathering is finished.", agent);

  if (res == TRUE) {
    /* step: call once imediately */
    res = priv_conn_check_tick_unlocked ((gpointer) agent);
    g_debug ("Agent %p : priv_conn_check_tick_unlocked returned %d", agent, res);

    /* step: schedule timer if not running yet */
    if (res && agent->conncheck_timer_id == 0) {
      agent->conncheck_timer_id = agent_timeout_add_with_context (agent, agent->timer_ta, priv_conn_check_tick, agent);
    }

    /* step: also start the keepalive timer */
    if (agent->keepalive_timer_id == 0) {
      agent->keepalive_timer_id = agent_timeout_add_with_context (agent, NICE_AGENT_TIMER_TR_DEFAULT, priv_conn_keepalive_tick, agent);
    }

  }

  g_debug ("Agent %p : conn_check_schedule_next returning %d", agent, res);
  return res;
}

/** 
 * Compares two connectivity check items. Checkpairs are sorted
 * in descending priority order, with highest priority item at
 * the start of the list.
 */
gint conn_check_compare (const CandidateCheckPair *a, const CandidateCheckPair *b)
{
  if (a->priority > b->priority)
    return -1;
  else if (a->priority < b->priority)
    return 1;
  return 0;
}

/**
 * Preprocesses a new connectivity check by going through list 
 * of a any stored early incoming connectivity checks from 
 * the remote peer. If a matching incoming check has been already
 * received, update the state of the new outgoing check 'pair'.
 * 
 * @param agent context pointer
 * @param stream which stream (of the agent)
 * @param component pointer to component object to which 'pair'has been added
 * @param pair newly added connectivity check
 */
static void priv_preprocess_conn_check_pending_data (NiceAgent *agent, Stream *stream, Component *component, CandidateCheckPair *pair)
{
  GSList *i;
  for (i = component->incoming_checks; i; i = i->next) {
    IncomingCheck *icheck = i->data;
    if (nice_address_equal (&icheck->from, &pair->remote->addr) &&
	icheck->local_socket == pair->local->sockptr) {
      g_debug ("Agent %p : Updating check %p with stored early-icheck %p, %p/%u/%u (agent/stream/component).", agent, pair, icheck, agent, stream->id, component->id);
      if (icheck->use_candidate)
	priv_mark_pair_nominated (agent, stream, component, pair->remote);
      priv_schedule_triggered_check (agent, stream, component, icheck->local_socket, pair->remote, icheck->use_candidate);
    }
  }
}

/**
 * Handle any processing steps for connectivity checks after
 * remote candidates have been set. This function handles
 * the special case where answerer has sent us connectivity
 * checks before the answer (containing candidate information),
 * reaches us. The special case is documented in sect 7.2 
 * if ICE spec (ID-19).
 */
void conn_check_remote_candidates_set(NiceAgent *agent)
{
  GSList *i, *j, *k, *l;
  for (i = agent->streams; i ; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->conncheck_list; j ; j = j->next) {
      CandidateCheckPair *pair = j->data;
      Component *component = stream_find_component_by_id (stream, pair->component_id);
      gboolean match = FALSE;
      
      /* performn delayed processing of spec steps section 7.2.1.4,
	 and section 7.2.1.5 */
      priv_preprocess_conn_check_pending_data (agent, stream, component, pair);

      for (k = component->incoming_checks; k; k = k->next) {
	IncomingCheck *icheck = k->data;
	/* sect 7.2.1.3., "Learning Peer Reflexive Candidates", has to 
	 * be handled separately */
	for (l = component->remote_candidates; l; l = l->next) {
	  NiceCandidate *cand = l->data;
	  if (nice_address_equal (&icheck->from, &cand->addr)) {
	    match = TRUE;
	    break;
	  }
	}
	if (match != TRUE) {
	  /* note: we have gotten an incoming connectivity check from 
	   *       an address that is not a known remote candidate */
	  NiceCandidate *candidate = 
	    discovery_learn_remote_peer_reflexive_candidate (agent, 
							     stream, 
							     component, 
							     icheck->priority, 
							     &icheck->from, 
							     icheck->local_socket);
	  if (candidate) {
	    priv_schedule_triggered_check (agent, stream, component, icheck->local_socket, candidate, icheck->use_candidate);
	  }
	}
      }
    }
  }
}

/** 
 * Enforces the upper limit for connectivity checks as described
 * in ICE spec section 5.7.3 (ID-19). See also 
 * conn_check_add_for_candidate().
 */
static GSList *priv_limit_conn_check_list_size (GSList *conncheck_list, guint upper_limit)
{
  guint list_len = g_slist_length (conncheck_list);
  guint c = 0;
  GSList *result = conncheck_list;

  if (list_len > upper_limit) {
    c = list_len - upper_limit;
    if (c == list_len) {
      /* case: delete whole list */
      g_slist_foreach (conncheck_list, conn_check_free_item, NULL);
      g_slist_free (conncheck_list),
	result = NULL;
    }
    else {
      /* case: remove 'c' items from list end (lowest priority) */
      GSList *i, *tmp;

      g_assert (c > 0);
      i = g_slist_nth (conncheck_list, c - 1);

      tmp = i->next;
      i->next = NULL;

      if (tmp) {
	/* delete the rest of the connectivity check list */
	g_slist_foreach (tmp, conn_check_free_item, NULL);
	g_slist_free (tmp);
      }
    }
  }

  return result;
}

/**
 * Changes the selected pair for the component if 'pair' is nominated
 * and has higher priority than the currently selected pair. See
 * ICE sect 11.1.1. "Procedures for Full Implementations" (ID-19).
 */ 
static gboolean priv_update_selected_pair (NiceAgent *agent, Component *component, CandidateCheckPair *pair)
{
  g_assert (component);
  g_assert (pair);
  if (pair->priority > component->selected_pair.priority) {
    g_debug ("Agent %p : changing SELECTED PAIR for component %u: %s:%s (prio:%lu).", agent, 
	     component->id, pair->local->foundation, pair->remote->foundation, (long unsigned)pair->priority);
    component->selected_pair.local = pair->local;
    component->selected_pair.remote = pair->remote;
    component->selected_pair.priority = pair->priority;

    agent_signal_new_selected_pair (agent, pair->stream_id, component->id, pair->local->foundation, pair->remote->foundation);
  }

  return TRUE;
}

/**
 * Updates the check list state.
 *
 * Implements parts of the algorithm described in 
 * ICE sect 8.1.2. "Updating States" (ID-19): if for any 
 * component, all checks have been completed and have
 * failed, mark that component's state to NICE_CHECK_FAILED.
 *
 * Sends a component state changesignal via 'agent'.
 */
static void priv_update_check_list_failed_components (NiceAgent *agent, Stream *stream)
{
  GSList *i;
  /* note: emitting a signal might cause the client 
   *       to remove the stream, thus the component count
   *       must be fetched before entering the loop*/
  guint c, components = stream->n_components;

  /* note: iterate the conncheck list for each component separately */
  for (c = 0; c < components; c++) {
    for (i = stream->conncheck_list; i; i = i->next) {
      CandidateCheckPair *p = i->data;
      
      if (p->stream_id == stream->id &&
	  p->component_id == (c + 1)) {
	
	if (p->state != NICE_CHECK_FAILED)
	  break;
      }
    }

    /* note: all checks have failed */
    if (i == NULL)
      agent_signal_component_state_change (agent, 
					   stream->id,
					   (c + 1), /* component-id */
					   NICE_COMPONENT_STATE_FAILED);
  }
}

/**
 * Updates the check list state for a stream component.
 *
 * Implements the algorithm described in ICE sect 8.1.2 
 * "Updating States" (ID-19) as it applies to checks of 
 * a certain component. If there are any nominated pairs, 
 * ICE processing may be concluded, and component state is 
 * changed to READY.
 *
 * Sends a component state changesignal via 'agent'.
 */
static void priv_update_check_list_state_for_ready (NiceAgent *agent, Stream *stream, Component *component)
{
  GSList *i;
  guint succeeded = 0, nominated = 0;

  g_assert (component);

  /* step: search for at least one nominated pair */
  for (i = stream->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component->id) {
      if (p->state == NICE_CHECK_SUCCEEDED ||
	  p->state == NICE_CHECK_DISCOVERED) {
	++succeeded;
	if (p->nominated == TRUE) {
	  priv_prune_pending_checks (stream, p->component_id);
	  agent_signal_component_state_change (agent,
					       p->stream_id,
					       p->component_id,
					       NICE_COMPONENT_STATE_READY);
	}
      }
    }
  }
  
  g_debug ("Agent %p : conn.check list status: %u nominated, %u succeeded, c-id %u.", agent, nominated, succeeded, component->id);
}

/**
 * The remote party has signalled that the candidate pair
 * described by 'component' and 'remotecand' is nominated
 * for use.
 */
static void priv_mark_pair_nominated (NiceAgent *agent, Stream *stream, Component *component, NiceCandidate *remotecand)
{
  GSList *i;

  g_assert (component);

  /* step: search for at least one nominated pair */
  for (i = stream->conncheck_list; i; i = i->next) {
    CandidateCheckPair *pair = i->data;
    /* XXX: hmm, how to figure out to which local candidate the 
     *      check was sent to? let's mark all matching pairs
     *      as nominated instead */
    if (pair->remote == remotecand) {
      g_debug ("Agent %p : marking pair %p (%s) as nominated", agent, pair, pair->foundation);
      pair->nominated = TRUE;
      if (pair->state == NICE_CHECK_SUCCEEDED ||
	  pair->state == NICE_CHECK_DISCOVERED)
	priv_update_selected_pair (agent, component, pair);
      priv_update_check_list_state_for_ready (agent, stream, component);
    }
  }
}

/**
 * Creates a new connectivity check pair and adds it to
 * the agent's list of checks.
 */
static gboolean priv_add_new_check_pair (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *local, NiceCandidate *remote, NiceCheckState initial_state, gboolean use_candidate)
{
  gboolean result = FALSE;
  Stream *stream = agent_find_stream (agent, stream_id);
  CandidateCheckPair *pair = g_slice_new0 (CandidateCheckPair);
  if (pair) {
    GSList *modified_list = 
      g_slist_insert_sorted (stream->conncheck_list, pair, (GCompareFunc)conn_check_compare);
    if (modified_list) {
      /* step: allocation and addition succesful, do rest of the work */

      pair->agent = agent;
      pair->stream_id = stream_id;
      pair->component_id = component->id;;
      pair->local = local; 
      pair->remote = remote;
      g_snprintf (pair->foundation, NICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s", local->foundation, remote->foundation);

      pair->priority = agent_candidate_pair_priority (agent, local, remote);
      pair->state = initial_state;
      pair->nominated = use_candidate;
      pair->controlling = agent->controlling_mode;
      
      /* note: for the first added check */
      if (!stream->conncheck_list)
	stream->conncheck_state = NICE_CHECKLIST_RUNNING;
      stream->conncheck_list = modified_list;

      result = TRUE;
      g_debug ("Agent %p : added a new conncheck %p with foundation of '%s' to list %u.", agent, pair, pair->foundation, stream_id);

      /* implement the hard upper limit for number of 
	 checks (see sect 5.7.3 ICE ID-19): */
      stream->conncheck_list = 
	priv_limit_conn_check_list_size (stream->conncheck_list, agent->max_conn_checks);
      if (!stream->conncheck_list) {
	stream->conncheck_state = NICE_CHECKLIST_FAILED;  
	result = FALSE;
      }
    }
    else {
      /* memory alloc failed: list insert */
      conn_check_free_item (pair, NULL);
      stream->conncheck_state = NICE_CHECKLIST_FAILED;  
    }
  }
  else { /* memory alloc failed: new pair */
    stream->conncheck_state = NICE_CHECKLIST_FAILED;
  }

  return result;
}

/**
 * Forms new candidate pairs by matching the new remote candidate
 * 'remote_cand' with all existing local candidates of 'component'.
 * Implements the logic described in ICE sect 5.7.1. "Forming Candidate
 * Pairs" (ID-19).
 *
 * @param agent context
 * @param component pointer to the component
 * @param remote remote candidate to match with
 *
 * @return number of checks added, negative on fatal errors
 */
int conn_check_add_for_candidate (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *remote)
{
  GSList *i;
  int added = 0; 

  for (i = component->local_candidates; i ; i = i->next) {

    NiceCandidate *local = i->data;

    /* note: match pairs only if transport and address family are the same */
    if (local->transport == remote->transport &&
	local->addr.s.addr.sa_family == remote->addr.s.addr.sa_family) {

      gboolean result;

      /* note: do not create pairs where local candidate is 
       *       a srv-reflexive (ICE 5.7.3. "Pruning the Pairs" ID-19) */
      if (local->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE)
	continue;

      result = priv_add_new_check_pair (agent, stream_id, component, local, remote, NICE_CHECK_FROZEN, FALSE);
      if (result) {
	++added;
	agent_signal_component_state_change (agent, 
					     stream_id,
					     component->id,
					     NICE_COMPONENT_STATE_CONNECTING);
      }
      else {
	added = -1;
	break;
      }
    }
  }

  return added;
}

/**
 * Frees the CandidateCheckPair structure pointer to 
 * by 'user data'. Compatible with g_slist_foreach().
 */
void conn_check_free_item (gpointer data, gpointer user_data)
{
  CandidateCheckPair *pair = data;
  g_assert (user_data == NULL);
  if (pair->stun_ctx)
    stun_bind_cancel (pair->stun_ctx), 
      pair->stun_ctx = NULL;
  g_slice_free (CandidateCheckPair, pair);
}

/**
 * Frees all resources of all connectivity checks.
 */
void conn_check_free (NiceAgent *agent)
{
  GSList *i;
  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;

    if (stream->conncheck_list) {
      g_slist_foreach (stream->conncheck_list, conn_check_free_item, NULL);
      g_slist_free (stream->conncheck_list),
	stream->conncheck_list = NULL;
      stream->conncheck_state = NICE_CHECKLIST_NOT_STARTED;
    }
  }

  if (agent->conncheck_timer_id) {
    g_source_remove (agent->conncheck_timer_id),
      agent->conncheck_timer_id = 0;
  }
}

/**
 * Prunes the list of connectivity checks for items related
 * to stream 'stream_id'. 
 *
 * @return TRUE on success, FALSE on a fatal error
 */
gboolean conn_check_prune_stream (NiceAgent *agent, Stream *stream)
{
  CandidateCheckPair *pair;
  GSList *i;

  for (i = stream->conncheck_list; i ; ) {
    GSList *next = i->next;
    pair = i->data;

    g_assert (pair->stream_id == stream->id);

    stream->conncheck_list = 
      g_slist_remove (stream->conncheck_list, pair);
    conn_check_free_item (pair, NULL);
    i = next;
    if (!stream->conncheck_list)
      break;
  }

  if (!stream->conncheck_list) {
    stream->conncheck_state = NICE_CHECKLIST_NOT_STARTED;
    conn_check_free (agent);
  }

  /* return FALSE if there was a memory allocation failure */
  if (stream->conncheck_list == NULL && i != NULL)
    return FALSE;

  return TRUE;
}


/**
 * Fills 'dest' with a username string for use in an outbound connectivity
 * checks. No more than 'dest_len' characters (including terminating
 * NULL) is ever written to the 'dest'.
 */
static gboolean priv_create_check_username (NiceAgent *agent, CandidateCheckPair *pair, gchar *dest, guint dest_len)
{
  Stream *stream;

  if (pair &&
      pair->remote && pair->remote->username &&
      pair->local && pair->local->username) {
    g_snprintf (dest, dest_len, "%s%s%s", pair->remote->username,
        agent->compatibility == NICE_COMPATIBILITY_ID19 ? ":" : "",
        pair->local->username);
    return TRUE;
  }

  stream = agent_find_stream (agent, pair->stream_id);
  if (stream) {
    g_snprintf (dest, dest_len, "%s%s%s", stream->remote_ufrag,
        agent->compatibility == NICE_COMPATIBILITY_ID19 ? ":" : "",
        stream->local_ufrag);
    return TRUE;
  }

  return FALSE;
}

/**
 * Returns a password string for use in an outbound connectivity
 * check.
 */
static const gchar *priv_create_check_password (NiceAgent *agent, CandidateCheckPair *pair)
{
  Stream *stream;

  if (pair &&
      pair->remote && pair->remote->password)
    return pair->remote->password;

  stream = agent_find_stream (agent, pair->stream_id);
  if (stream)
    return stream->remote_password;

  return NULL;
}

/**
 * Sends a connectivity check over candidate pair 'pair'.
 *
 * @return zero on success, non-zero on error
 */
int conn_check_send (NiceAgent *agent, CandidateCheckPair *pair)
{

  /* note: following information is supplied:
   *  - username (for USERNAME attribute)
   *  - password (for MESSAGE-INTEGRITY)
   *  - priority (for PRIORITY)
   *  - ICE-CONTROLLED/ICE-CONTROLLING (for role conflicts)
   *  - USE-CANDIDATE (if sent by the controlling agent)
   */

  guint32 priority =
    nice_candidate_ice_priority_full (
      NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE,
      1,
      pair->local->component_id);

  gchar uname[NICE_STREAM_MAX_UNAME];
  gboolean username_filled = 
     priv_create_check_username (agent, pair, uname, sizeof (uname));
  const gchar *password = priv_create_check_password (agent, pair);

  bool controlling = agent->controlling_mode;
 /* XXX: add API to support different nomination modes: */
  bool cand_use = controlling;

  struct sockaddr sockaddr;
  unsigned int timeout;

  memset (&sockaddr, 0, sizeof (sockaddr)); 

  nice_address_copy_to_sockaddr (&pair->remote->addr, &sockaddr);

#ifndef NDEBUG
  {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (&pair->remote->addr, tmpbuf);
    g_debug ("Agent %p : STUN-CC REQ to '%s:%u', socket=%u, pair=%s (c-id:%u), tie=%llu, username='%s', password='%s', priority=%u.", agent, 
	     tmpbuf,
	     ntohs(((struct sockaddr_in*)(&sockaddr))->sin_port), 
	     pair->local->sockptr->fileno,
	     pair->foundation, pair->component_id,
	     (unsigned long long)agent->tie_breaker,
	     uname, password, priority);

  }
#endif

  if (cand_use) 
    pair->nominated = controlling;

  if (username_filled) {

    if (pair->stun_ctx)
      stun_bind_cancel (pair->stun_ctx);

    stun_conncheck_start (&pair->stun_ctx, pair->local->sockptr->fileno,
			  &sockaddr, sizeof (sockaddr),
			  uname, password,
			  cand_use, controlling, priority,
			  agent->tie_breaker);

    timeout = stun_bind_timeout (pair->stun_ctx);
    /* note: convert from milli to microseconds for g_time_val_add() */
    g_get_current_time (&pair->next_tick);
    g_time_val_add (&pair->next_tick, timeout * 1000);
    pair->traffic_after_tick = TRUE; /* for keepalive timer */
  }
    
  return 0;
}

/**
 * Implemented the pruning steps described in ICE sect 8.1.2
 * "Updating States" (ID-19) after a pair has been nominated.
 *
 * @see priv_update_check_list_state_failed_components()
 */
static void priv_prune_pending_checks (Stream *stream, guint component_id)
{
  GSList *i;

  /* step: cancel all FROZEN and WAITING pairs for the component */
  for (i = stream->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component_id) {
      if (p->state == NICE_CHECK_FROZEN ||
	  p->state == NICE_CHECK_WAITING)
	p->state = NICE_CHECK_CANCELLED;
      
      /* note: a SHOULD level req. in ICE 8.1.2. "Updating States" (ID-19) */
      if (p->state == NICE_CHECK_IN_PROGRESS) {
	if (p->stun_ctx)
	  stun_bind_cancel (p->stun_ctx),
	    p->stun_ctx = NULL;
	p->state = NICE_CHECK_CANCELLED;
      }
    }
  }
}

/**
 * Schedules a triggered check after a succesfully inbound 
 * connectivity check. Implements ICE sect 7.2.1.4 "Triggered Checks" (ID-19).
 * 
 * @param agent self pointer
 * @param component the check is related to
 * @param local_socket socket from which the inbound check was received
 * @param remote_cand remote candidate from which the inbound check was sent
 * @param use_candidate whether the original check had USE-CANDIDATE attribute set
 */
static gboolean priv_schedule_triggered_check (NiceAgent *agent, Stream *stream, Component *component, NiceUDPSocket *local_socket, NiceCandidate *remote_cand, gboolean use_candidate)
{
  GSList *i;
  gboolean result = FALSE;

  for (i = stream->conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (p->component_id == component->id &&
	  p->remote == remote_cand &&
	  p->local->sockptr == local_socket) {

	g_debug ("Agent %p : Found a matching pair %p for triggered check.", agent, p);
	
	if (p->state == NICE_CHECK_WAITING ||
	    p->state == NICE_CHECK_FROZEN)
	  priv_conn_check_initiate (agent, p);

	if (p->state == NICE_CHECK_IN_PROGRESS) {
	  /* XXX: according to ICE 7.2.1.4 "Triggered Checks" (ID-19),
	   * we should cancel the existing one, and send a new one...? :P */
	  g_debug ("Agent %p : Skipping triggered check, already in progress..", agent);
	}
	else if (p->state == NICE_CHECK_SUCCEEDED ||
		 p->state == NICE_CHECK_DISCOVERED) {
	  g_debug ("Agent %p : Skipping triggered check, already completed..", agent); 
	  /* note: this is a bit unsure corner-case -- let's do the
	     same state update as for processing responses to our own checks */
	  priv_update_check_list_state_for_ready (agent, stream, component);

	  /* note: to take care of the controlling-controlling case in 
	   *       aggressive nomination mode, send a new triggered
	   *       check to nominate the pair */
	  if (agent->controlling_mode)
	    priv_conn_check_initiate (agent, p);
	}

	/* note: the spec says the we SHOULD retransmit in-progress
	 *       checks immediately, but we won't do that now */

	return TRUE;
      }
  }

  {
    NiceCandidate *local = NULL;

    for (i = component->local_candidates; i ; i = i->next) {
      local = i->data;
      if (local->sockptr == local_socket)
	break;
    }    
    if (i) {
      g_debug ("Agent %p : Adding a triggered check to conn.check list (local=%p).", agent, local);
      result = priv_add_new_check_pair (agent, stream->id, component, local, remote_cand, NICE_CHECK_WAITING, use_candidate);
    }
    else
      g_debug ("Agent %p : Didn't find a matching pair for triggered check (remote-cand=%p).", agent, remote_cand);
  }

  return result;
}


/**
 * Sends a reply to an succesfully received STUN connectivity 
 * check request. Implements parts of the ICE spec section 7.2 (STUN
 * Server Procedures).
 *
 * @param agent context pointer
 * @param stream which stream (of the agent)
 * @param component which component (of the stream)
 * @param rcand remote candidate from which the request came, if NULL,
 *        the response is sent immediately but no other processing is done
 * @param toaddr address to which reply is sent
 * @param udp_socket the socket over which the request came
 * @param rbuf_len length of STUN message to send
 * @param rbuf buffer containing the STUN message to send
 * @param use_candidate whether the request had USE_CANDIDATE attribute
 * 
 * @pre (rcand == NULL || nice_address_equal(rcand->addr, toaddr) == TRUE)
 */
static void priv_reply_to_conn_check (NiceAgent *agent, Stream *stream, Component *component, NiceCandidate *rcand, const NiceAddress *toaddr, NiceUDPSocket *udp_socket, size_t  rbuf_len, uint8_t *rbuf, gboolean use_candidate)
{
  g_assert (rcand == NULL || nice_address_equal(&rcand->addr, toaddr) == TRUE);

#ifndef NDEBUG
  {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (toaddr, tmpbuf);
    g_debug ("Agent %p : STUN-CC RESP to '%s:%u', socket=%u, len=%u, cand=%p (c-id:%u), use-cand=%d.", agent,
	     tmpbuf,
	     nice_address_get_port (toaddr),
	     udp_socket->fileno,
	     (unsigned)rbuf_len,
	     rcand, component->id,
	     (int)use_candidate);
  }
#endif

  nice_udp_socket_send (udp_socket, toaddr, rbuf_len, (const gchar*)rbuf);
  
  if (rcand) {
    if (use_candidate)
      priv_mark_pair_nominated (agent, stream, component, rcand);

    /* note: upon succesful check, make the reserve check immediately */
    priv_schedule_triggered_check (agent, stream, component, udp_socket, rcand, use_candidate);
  }
}

/**
 * Stores information of an incoming STUN connectivity check
 * for later use. This is only needed when a check is received
 * before we get information about the remote candidates (via
 * SDP or other signaling means).
 *
 * @return non-zero on error, zero on success
 */
static int priv_store_pending_check (NiceAgent *agent, Component *component, const NiceAddress *from, NiceUDPSocket *udp_socket, uint32_t priority, gboolean use_candidate)
{
  IncomingCheck *icheck;
  g_debug ("Agent %p : Storing pending check.", agent);

  if (component->incoming_checks &&
      g_slist_length (component->incoming_checks) >= 
      NICE_AGENT_MAX_REMOTE_CANDIDATES) {
    g_debug ("Agent %p : WARN: unable to store information for early incoming check.", agent);
    return -1;
  }

  icheck = g_slice_new0 (IncomingCheck);
  if (icheck) {
    GSList *pending = g_slist_append (component->incoming_checks, icheck);
    if (pending) {
      component->incoming_checks = pending;
      icheck->from = *from;
      icheck->local_socket = udp_socket;
      icheck->priority = priority;
      icheck->use_candidate = use_candidate;
      return 0;
    }
  }

  return -1;
}

/**
 * Adds a new pair, discovered from an incoming STUN response, to 
 * the connectivity check list.
 *
 * @return created pair, or NULL on fatal (memory allocation) errors
 */
static CandidateCheckPair *priv_add_peer_reflexive_pair (NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *local_cand, CandidateCheckPair *parent_pair)
{
  CandidateCheckPair *pair = g_slice_new0 (CandidateCheckPair);
  if (pair) {
    Stream *stream = agent_find_stream (agent, stream_id);
    GSList *modified_list = g_slist_append (stream->conncheck_list, pair);
    if (modified_list) {
      stream->conncheck_list = modified_list;
      pair->agent = agent;
      pair->stream_id = stream_id;
      pair->component_id = component_id;;
      pair->local = local_cand;
      pair->remote = parent_pair->remote;
      pair->state = NICE_CHECK_DISCOVERED;
      g_snprintf (pair->foundation, NICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s", local_cand->foundation, parent_pair->remote->foundation);
      if (agent->controlling_mode == TRUE)
	pair->priority = nice_candidate_pair_priority (local_cand->priority, parent_pair->priority);
      else
	pair->priority = nice_candidate_pair_priority (parent_pair->priority, local_cand->priority);
      pair->nominated = FALSE;
      pair->controlling = agent->controlling_mode;
      g_debug ("Agent %p : added a new peer-discovered pair with foundation of '%s'.", agent, pair->foundation);
      return pair;
    }
  }

  return NULL;
}

/**
 * Recalculates priorities of all candidate pairs. This
 * is required after a conflict in ICE roles.
 */
static void priv_recalculate_pair_priorities (NiceAgent *agent)
{
  GSList *i, *j;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->conncheck_list; j; j = j->next) {
      CandidateCheckPair *p = j->data;
      p->priority = agent_candidate_pair_priority (agent, p->local, p->remote);
    }
  }
}

/**
 * Change the agent role if different from 'control'. Can be
 * initiated both by handling of incoming connectivity checks,
 * and by processing the responses to checks sent by us.
 */
static void priv_check_for_role_conflict (NiceAgent *agent, gboolean control)
{
  /* role conflict, change mode; wait for a new conn. check */
  if (control != agent->controlling_mode) {
    g_debug ("Agent %p : Role conflict, changing agent role to %d.", agent, control);
    agent->controlling_mode = control;
    /* the pair priorities depend on the roles, so recalculation
     * is needed */
    priv_recalculate_pair_priorities (agent);
  }
  else 
    g_debug ("Agent %p : Role conflict, agent role already changed to %d.", agent, control);
}

/** 
 * Checks whether the mapped address in connectivity check response 
 * matches any of the known local candidates. If not, apply the
 * mechanism for "Discovering Peer Reflexive Candidates" ICE ID-19)
 *
 * @param agent context pointer
 * @param stream which stream (of the agent)
 * @param component which component (of the stream)
 * @param p the connectivity check pair for which we got a response
 * @param socketptr socket used to send the reply
 * @param mapped_sockaddr mapped address in the response
 *
 * @return pointer to a new pair if one was created, otherwise NULL
 */
static CandidateCheckPair *priv_process_response_check_for_peer_reflexive(NiceAgent *agent, Stream *stream, Component *component, CandidateCheckPair *p, NiceUDPSocket *sockptr, struct sockaddr *mapped_sockaddr)
{
  CandidateCheckPair *new_pair = NULL;
  NiceAddress mapped;
  GSList *j;
  gboolean local_cand_matches = FALSE;

  nice_address_set_from_sockaddr (&mapped, mapped_sockaddr);

  for (j = component->local_candidates; j; j = j->next) {
    NiceCandidate *cand = j->data;
    if (nice_address_equal (&mapped, &cand->addr)) {
      local_cand_matches = TRUE; 
      break;
    }
  }

  if (local_cand_matches == TRUE) {
    /* note: this is same as "adding to VALID LIST" in the spec
       text */
    p->state = NICE_CHECK_SUCCEEDED;
    g_debug ("Agent %p : conncheck %p SUCCEEDED.", agent, p);
    priv_conn_check_unfreeze_related (agent, stream, p);
  }
  else {
    NiceCandidate *cand =
      discovery_add_peer_reflexive_candidate (agent,
					      stream->id,
					      component->id,
					      &mapped,
					      sockptr);
    p->state = NICE_CHECK_FAILED;
	    
    /* step: add a new discovered pair (see ICE 7.1.2.2.2
	       "Constructing a Valid Pair" (ID-19)) */
    new_pair = priv_add_peer_reflexive_pair (agent, stream->id, component->id, cand, p);
    g_debug ("Agent %p : conncheck %p FAILED, %p DISCOVERED.", agent, p, new_pair);
  }

  return new_pair;
}

/**
 * Tries to match STUN reply in 'buf' to an existing STUN connectivity
 * check transaction. If found, the reply is processed. Implements
 * section 7.1.2 "Processing the Response" of ICE spec (ID-19).
 * 
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_conn_check_request (NiceAgent *agent, Stream *stream, Component *component, NiceUDPSocket *sockptr, const NiceAddress *from, gchar *buf, guint len)
{
  struct sockaddr sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  GSList *i;
  ssize_t res;
  gboolean trans_found = FALSE;

  for (i = stream->conncheck_list; i && trans_found != TRUE; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->stun_ctx) {
      res = stun_bind_process (p->stun_ctx, buf, len, &sockaddr, &socklen); 
      g_debug ("Agent %p : stun_bind_process/conncheck for %p res %d (%s) (controlling=%d).", agent, p, (int)res, strerror (res), agent->controlling_mode);
      if (res == 0) {
	/* case: found a matching connectivity check request */

	CandidateCheckPair *ok_pair = NULL;

	g_debug ("Agent %p : conncheck %p MATCHED.", agent, p);
	p->stun_ctx = NULL;

	/* step: verify that response came from the same IP address we
	 *       sent the original request to (see 7.1.2.1. "Failure
	 *       Cases") */
	if (nice_address_equal (from, &p->remote->addr) != TRUE) {
	  p->state = NICE_CHECK_FAILED;	
	  g_debug ("Agent %p : conncheck %p FAILED (mismatch of source address).", agent, p); 
	  trans_found = TRUE;
	  break;
	}
	
	/* note: CONNECTED but not yet READY, see docs */

	/* step: handle the possible case of a peer-reflexive
	 *       candidate where the mapped-address in response does
	 *       not match any local candidate, see 7.1.2.2.1
	 *       "Discovering Peer Reflexive Candidates" ICE ID-19) */

	ok_pair = priv_process_response_check_for_peer_reflexive(agent, stream, component,  p, sockptr, &sockaddr);
	if (!ok_pair)
	  ok_pair = p;

	/* step: notify the client of a new component state (must be done
	 *       before the possible check list state update step */
	agent_signal_component_state_change (agent, 
					     stream->id,
					     component->id,
					     NICE_COMPONENT_STATE_CONNECTED);


	/* step: updating nominated flag (ICE 7.1.2.2.4 "Updating the
	   Nominated Flag" (ID-19) */
	if (ok_pair->nominated == TRUE) 
	  priv_update_selected_pair (agent, component, ok_pair);

	/* step: update pair states (ICE 7.1.2.2.3 "Updating pair
	   states" and 8.1.2 "Updating States", ID-19) */
	priv_update_check_list_state_for_ready (agent, stream, component);

	trans_found = TRUE;
      }
      else if (res == ECONNRESET) {
	/* case: role conflict error, need to restart with new role */
	g_debug ("Agent %p : conncheck %p ROLE CONFLICT, restarting", agent, p);
	
	/* note: our role might already have changed due to an
	 * incoming request, but if not, change role now;
	 * follows ICE 7.1.2.1 "Failure Cases" (ID-19) */
	priv_check_for_role_conflict (agent, !p->controlling);

	p->stun_ctx = NULL;
	p->state = NICE_CHECK_WAITING;
	trans_found = TRUE;
      }
      else if (res != EAGAIN) {
	/* case: STUN error, the check STUN context was freed */
	g_debug ("Agent %p : conncheck %p FAILED.", agent, p);
	p->stun_ctx = NULL;
	trans_found = TRUE;
      }
      else {
	/* case: STUN could not parse, skip */
	g_assert (res == EAGAIN);
	
	g_debug ("Agent %p : conncheck %p SKIPPED", agent, p);
      }
    }
  }
  
  return trans_found;
}

/**
 * Tries to match STUN reply in 'buf' to an existing STUN discovery
 * transaction. If found, a reply is sent.
 * 
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_discovery_request (NiceAgent *agent, gchar *buf, guint len)
{
  struct sockaddr sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  GSList *i;
  ssize_t res;
  gboolean trans_found = FALSE;

  for (i = agent->discovery_list; i && trans_found != TRUE; i = i->next) {
    CandidateDiscovery *d = i->data;
    if (d->stun_ctx) {
      res = stun_bind_process (d->stun_ctx, buf, len, &sockaddr, &socklen); 
      g_debug ("Agent %p : stun_bind_process/disc for %p res %d (%s).", agent, d, (int)res,
               strerror (res));
      if (res == 0) {
	/* case: succesful binding discovery, create a new local candidate */
	NiceAddress niceaddr;
        nice_address_set_from_sockaddr (&niceaddr, &sockaddr);

	discovery_add_server_reflexive_candidate (
	  d->agent,
	  d->stream->id,
	  d->component->id,
	  &niceaddr,
	  d->nicesock);
	
	d->stun_ctx = NULL;
	d->done = TRUE;
	trans_found = TRUE;
      }
      else if (res != EAGAIN) {
	/* case: STUN error, the check STUN context was freed */
	d->stun_ctx = NULL;
	d->done = TRUE;
	trans_found = TRUE;
      }
      else {
	g_assert (res == EAGAIN);
      }
    }
  }

  return trans_found;
}

/**
 * Processing an incoming STUN message.
 *
 * @param agent self pointer
 * @param stream stream the packet is related to
 * @param component component the packet is related to
 * @param udp_socket UDP socket from which the packet was received
 * @param from address of the sender
 * @param buf message contents
 * @param buf message length
 *
 * @pre contents of 'buf' is a STUN message
 * 
 * @return XXX (what FALSE means exactly?)
 */
gboolean conn_check_handle_inbound_stun (NiceAgent *agent, Stream *stream, Component *component, NiceUDPSocket *udp_socket, const NiceAddress *from, gchar *buf, guint len)
{
  struct sockaddr sockaddr;
  uint8_t rbuf[MAX_STUN_DATAGRAM_PAYLOAD];
  ssize_t res;
  size_t rbuf_len = sizeof (rbuf);
  bool control = agent->controlling_mode;
  gchar uname[NICE_STREAM_MAX_UNAME];

  nice_address_copy_to_sockaddr (from, &sockaddr);
  g_snprintf (uname, sizeof (uname), "%s:%s", stream->local_ufrag,
              stream->remote_ufrag);

  /* note: contents of 'buf' already validated, so it is 
   *       a valid and fully received STUN message */

  g_debug ("Agent %p : inbound STUN packet for %u/%u (stream/component):", agent, stream->id, component->id);

  /* note: ICE  7.2. "STUN Server Procedures" (ID-19) */

  res = stun_conncheck_reply (rbuf, &rbuf_len, (const uint8_t*)buf, &sockaddr, sizeof (sockaddr), 
                              stream->local_ufrag, stream->local_password,
                              &control, agent->tie_breaker, agent->compatibility);

  if (res == EACCES)
    priv_check_for_role_conflict (agent, control);

  if (res == 0 || res == EACCES) {
    /* case 1: valid incoming request, send a reply/error */
    
    GSList *i;
    bool use_candidate = 
      stun_conncheck_use_candidate ((const uint8_t*)buf);
    uint32_t priority = stun_conncheck_priority ((const uint8_t*)buf);

    if (agent->controlling_mode) 
      use_candidate = TRUE;

    if (stream->initial_binding_request_received != TRUE)
      agent_signal_initial_binding_request_received (agent, stream);

    if (component->remote_candidates == NULL) {
      /* case: We've got a valid binding request to a local candidate
       *       but we do not yet know remote credentials nor
       *       candidates. As per sect 7.2 of ICE (ID-19), we send a reply
       *       immediately but postpone all other processing until
       *       we get information about the remote candidates */

      /* step: send a reply immediately but postpone other processing */
      priv_reply_to_conn_check (agent, stream, component, NULL, from, udp_socket, rbuf_len, rbuf, use_candidate);
      priv_store_pending_check (agent, component, from, udp_socket, priority, use_candidate);
    }
    else {
      for (i = component->remote_candidates; i; i = i->next) {
	NiceCandidate *cand = i->data;
	if (nice_address_equal (from, &cand->addr)) {
	  priv_reply_to_conn_check (agent, stream, component, cand, &cand->addr, udp_socket, rbuf_len, rbuf, use_candidate);
	  break;
	}
      }
      
      if (i == NULL) {
	NiceCandidate *candidate;
	g_debug ("Agent %p : No matching remote candidate for incoming check -> peer-reflexive candidate.", agent);
	candidate = discovery_learn_remote_peer_reflexive_candidate (
								     agent, stream, component, priority, from, udp_socket);
	if (candidate)
	  priv_reply_to_conn_check (agent, stream, component, candidate, &candidate->addr, udp_socket, rbuf_len, rbuf, use_candidate);
      }
    }
  }
  else if (res == EINVAL) {
    /* case 2: not a new request, might be a reply...  */

    gboolean trans_found = FALSE;

    /* note: ICE sect 7.1.2. "Processing the Response" (ID-19) */

    /* step: let's try to match the response to an existing check context */
    if (trans_found != TRUE)
      trans_found = 
	priv_map_reply_to_conn_check_request (agent, stream, component, udp_socket, from, buf, len);

    /* step: let's try to match the response to an existing discovery */
    if (trans_found != TRUE)
      trans_found = 
	priv_map_reply_to_discovery_request (agent, buf, len);

    if (trans_found != TRUE)
      g_debug ("Agent %p : Unable to match to an existing transaction, probably a keepalive.", agent);
  }
  else {
    g_debug ("Agent %p : Invalid STUN packet, ignoring... %s", agent, strerror(errno));
    return FALSE;
  }

  return TRUE;
}
