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

static inline int priv_timer_expired (GTimeVal *restrict timer, GTimeVal *restrict now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

static void priv_update_check_list_state (NiceAgent *agent, Stream *stream);

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
  g_time_val_add (&pair->next_tick, agent->timer_ta * 10);
  pair->state = NICE_CHECK_IN_PROGRESS;
  conn_check_send (agent, pair);
  return TRUE;
}

/**
 * Unfreezes the next connectivity check in the list. Follows the
 * algorithm (2.) defined in 5.7.4 (Computing States) of the ICE spec
 * (ID-17), with some exceptions (see comments in code).
 *
 * See also sect 7.1.2.2.3 (Updating Pair States), and
 * priv_conn_check_unfreeze_related().
 * 
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static gboolean priv_conn_check_unfreeze_next (NiceAgent *agent, GSList *conncheck_list)
{
  CandidateCheckPair *pair = NULL;
  guint64 max_frozen_priority = 0;
  GSList *i;
  guint c;
  guint max_components = 0;
  gboolean frozen = FALSE;

  /* step: calculate the max number of components across streams */
  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    if (stream->n_components > max_components)
      max_components = stream->n_components;
  }

  /* note: the pair list is already sorted so separate prio check
   *       is not needed */

  /* XXX: the unfreezing is implemented a bit differently than in the
   *      current ICE spec, but should still be interoperate:
   *   - checks are not grouped by foundation
   *   - one frozen check is unfrozen (lowest component-id, highest
   *     priority)
   */

  for (c = 0; (pair == NULL) && c < max_components; c++) {
    for (i = conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (p->component_id == c + 1) {
	if (p->state == NICE_CHECK_FROZEN) {
	  frozen = TRUE;
	  if (p->priority > max_frozen_priority) {
	    max_frozen_priority = p->priority;
	    pair = p;
	  }
	}
      }
    }
  }
  
  if (pair) {
    g_debug ("Pair %p with s/c-id %u/%u (%s) unfrozen.", pair, pair->stream_id, pair->component_id, pair->foundation);
    pair->state = NICE_CHECK_WAITING;
    return TRUE;
  }

  return FALSE;
}

/**
 * Unfreezes the next next connectivity check in the list after
 * check 'success_check' has succesfully completed.
 *
 * See sect 7.1.2.2.3 (Updating Pair States) of ICE spec (ID-17).
 * 
 * @param agent context
 * @param ok_check a connectivity check that has just completed
 *
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static void priv_conn_check_unfreeze_related (NiceAgent *agent, CandidateCheckPair *ok_check)
{
  GSList *i, *j;
  Stream *stream;
  guint unfrozen = 0;

  g_assert (ok_check);
  g_assert (ok_check->state == NICE_CHECK_SUCCEEDED);

  /* step: perform the step (1) of 'Updating Pair States' */
  for (i = agent->conncheck_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;
   
    if (p->stream_id == ok_check->stream_id) {
      if (p->state == NICE_CHECK_FROZEN &&
	  strcmp (p->foundation, ok_check->foundation) == 0) {
	g_debug ("Unfreezing check %p (after succesful check %p).", p, ok_check);
	p->state = NICE_CHECK_WAITING;
      }
    }
  }

  /* step: perform the step (2) of 'Updating Pair States' */
  stream = agent_find_stream (agent, ok_check->stream_id);
  if (stream_all_components_ready (stream)) {
    /* step: unfreeze checks from other streams */
    for (i = agent->streams; i ; i = i->next) {
      Stream *s = i->data;
      for (j = agent->conncheck_list; j ; j = j->next) {
	CandidateCheckPair *p = j->data;

	if (p->stream_id == s->id &&
	    p->stream_id != ok_check->stream_id) {
	  if (p->state == NICE_CHECK_FROZEN &&
	      strcmp (p->foundation, ok_check->foundation) == 0) {
	    g_debug ("Unfreezing check %p from stream %u (after succesful check %p).", p, s->id, ok_check);
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
    priv_conn_check_unfreeze_next (agent, agent->conncheck_list);
}

/**
 * Timer callback that handles initiating and managing connectivity
 * checks (paced by the Ta timer).
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_conn_check_tick (gpointer pointer)
{
  CandidateCheckPair *pair = NULL;
  NiceAgent *agent = pointer;
  GSList *i;
  gboolean keep_timer_going = FALSE;
  GTimeVal now;
  int frozen = 0, inprogress = 0, waiting = 0, succeeded = 0, nominated = 0;

  pair = priv_conn_check_find_next_waiting (agent->conncheck_list);

  if (pair) {
    priv_conn_check_initiate (agent, pair);
    keep_timer_going = TRUE;
  }

  g_get_current_time (&now);

  for (i = agent->conncheck_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;
    
    if (p->state == NICE_CHECK_IN_PROGRESS) {
      /* note: macro from sys/time.h but compatible with GTimeVal */
      if (p->stun_ctx == NULL) {
	g_debug ("STUN connectivity check was cancelled, marking as done.");
	p->state = NICE_CHECK_FAILED;
      }
      else if (priv_timer_expired (&p->next_tick, &now)) {
	int res = stun_bind_elapse (p->stun_ctx);
	if (res == EAGAIN) {
	  /* case: not ready, so schedule a new timeout */
	  unsigned int timeout = stun_bind_timeout (p->stun_ctx);
	  
	  /* note: convert from milli to microseconds for g_time_val_add() */
	  g_get_current_time (&p->next_tick);
	  g_time_val_add (&p->next_tick, timeout * 10);
	  
	  keep_timer_going = TRUE;
	  p->traffic_after_tick = TRUE; /* for keepalive timer */
	}
	else {
	  /* case: error, abort processing */
	  g_debug ("Retransmissions failed, giving up on connectivity check %p", p);
	  p->state = NICE_CHECK_FAILED;
	  p->stun_ctx = NULL;
	}
      }
    }
    
    if (p->state == NICE_CHECK_FROZEN)
      ++frozen;
    else if (p->state == NICE_CHECK_IN_PROGRESS)
      ++inprogress;
    else if (p->state == NICE_CHECK_WAITING)
      ++waiting;
    else if (p->state == NICE_CHECK_SUCCEEDED)
      ++succeeded;
    
    if (p->nominated)
      ++nominated;
  }
  
  /* note: keep the timer going as long as there is work to be done */
  if (frozen || inprogress || waiting ||
      (succeeded && nominated == 0))
    keep_timer_going = TRUE;

  /* note: if no waiting checks, unfreeze one check */
  if (!waiting && frozen)
    priv_conn_check_unfreeze_next (agent, agent->conncheck_list);

  /* step: nominate some candidate
   *   -  no work left but still no nominated checks (possibly
   *      caused by a controlling-controlling role conflict)
   */
  if (agent->controlling_mode &&
      (!frozen && !inprogress && !waiting && !nominated)) {
    g_debug ("no nominated checks, resending checks to select one");
    for (i = agent->conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      /* XXX: should we pick highest priority one? probably yes. */
      if (p->state == NICE_CHECK_SUCCEEDED ||
	  p->state == NICE_CHECK_DISCOVERED) {
	g_debug ("restarting check %p as the nominated pair.", p);
	p->nominated = TRUE;
	priv_conn_check_initiate (agent, p);	
	keep_timer_going = TRUE;
      }
    }
  }

#ifndef NDEBUG
  {
    static int tick_counter = 0;
    if (tick_counter++ % 50 == 0 || keep_timer_going != TRUE)
      g_debug ("timer(%p) tick #%d: %d frozen, %d in-progress, %d waiting, %d succeeded, %d nominated.", 
	       agent, tick_counter, frozen, inprogress, waiting, succeeded, nominated);
  }
#endif
  
  /* step: stop timer if no work left */
  if (keep_timer_going != TRUE) {
    g_debug ("%s: stopping conncheck timer", G_STRFUNC);
    for (i = agent->streams; i; i = i->next) {
      Stream *stream = i->data;
      priv_update_check_list_state (agent, stream);
    }
    conn_check_free (agent);
    agent->conncheck_state = NICE_CHECKLIST_COMPLETED;
    /* XXX: what to signal, is all processing now really done? */
    g_debug ("changing conncheck state to COMPLETED.");
  }

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
static gboolean priv_conn_keepalive_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  GSList *i, *j;
  int errors = 0;

  /* case 1: session established and media flowing
   *         (ref ICE sect 10 "Keepalives" ID-17)  */
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
	g_debug ("stun_bind_keepalive for pair %p res %d.", p, res);
	if (res < 0)
	  ++errors;
      }
      component->media_after_tick = FALSE;
    }
  }
  
  /* case 2: connectivity establishment ongoing
   *         (ref ICE sect 4.1.1.5 "Keeping Candidates Alive" ID-17)  */
  if (agent->conncheck_state == NICE_CHECKLIST_RUNNING) {
    for (i = agent->conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      
      if (p->traffic_after_tick != TRUE) {
	g_debug ("resending STUN-CC to keep the candidate alive (pair %p).", p);
	conn_check_send (agent, p);
      }
      p->traffic_after_tick = FALSE;
    }
  }
    
  if (errors) {
    g_debug ("%s: stopping keepalive timer", G_STRFUNC);
    return FALSE;
  }

  return TRUE;
}

/**
 * Initiates the next pending connectivity check.
 */
void conn_check_schedule_next (NiceAgent *agent)
{
  gboolean c = priv_conn_check_unfreeze_next (agent, agent->conncheck_list);

  if (agent->discovery_unsched_items > 0)
    g_debug ("WARN: starting conn checks before local candidate gathering is finished.");

  if (c == TRUE) {
    /* step: call once imediately */
    gboolean res = priv_conn_check_tick ((gpointer) agent);

    /* step: schedule timer if not running yet */
    if (agent->conncheck_timer_id == 0 && res != FALSE) 
      agent->conncheck_timer_id = 
	g_timeout_add (agent->timer_ta, priv_conn_check_tick, agent);

    /* step: also start the keepalive timer */
    if (agent->keepalive_timer_id == 0) 
      agent->keepalive_timer_id = 
	g_timeout_add (NICE_AGENT_TIMER_TR_DEFAULT, priv_conn_keepalive_tick, agent);

  }
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

static gboolean priv_add_new_check_pair (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *local, NiceCandidate *remote, NiceCheckState initial_state, gboolean use_candidate)
{
  gboolean result = FALSE;

  CandidateCheckPair *pair = g_slice_new0 (CandidateCheckPair);
  if (pair) {
    pair->agent = agent;
    pair->stream_id = stream_id;
    pair->component_id = component->id;;
    pair->local = local; 
    pair->remote = remote;
    g_snprintf (pair->foundation, NICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s", local->foundation, remote->foundation);
    
    if (agent->controlling_mode == TRUE)
      pair->priority = nice_candidate_pair_priority (local->priority, remote->priority);
    else
      pair->priority = nice_candidate_pair_priority (remote->priority, local->priority);
    pair->state = initial_state;
    pair->nominated = use_candidate;

    /* note: for the first added check */
    if (!agent->conncheck_list)
      agent->conncheck_state = NICE_CHECKLIST_RUNNING;
    
    {
      GSList *modified_list = 
	g_slist_insert_sorted (agent->conncheck_list, pair, (GCompareFunc)conn_check_compare);
      if (modified_list) {
	agent->conncheck_list = modified_list;
	result = TRUE;
	g_debug ("added a new conncheck %p with foundation of '%s'.", pair, pair->foundation);
      }
      else { /* memory alloc failed: list insert */
	conn_check_free_item (pair, NULL);
	agent->conncheck_state = NICE_CHECKLIST_FAILED;  
      }
    }	  
  }
  else { /* memory alloc failed: new pair */
    agent->conncheck_state = NICE_CHECKLIST_FAILED;
  }

  return result;
}

/**
 * Forms new candidate pairs by matching the new remote candidate
 * 'remote_cand' with all existing local candidates of 'component'.
 * Implements the logic described in ICE sect 5.7.1. "Forming Candidate
 * Pairs" (ID-17).
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
	local->addr.type == remote->addr.type) {

      gboolean result;

      /* note: do not create pairs where local candidate is 
       *       a srv-reflexive (ICE 5.7.3. "Pruning the Pairs" ID-17) */
      if (local->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE)
	continue;

      result = priv_add_new_check_pair (agent, stream_id, component, local, remote, NICE_CHECK_FROZEN, FALSE);
      if (result) {
	++added;
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
 * Frees all resources of agent's connectiviy checks.
 */
void conn_check_free (NiceAgent *agent)
{
  if (agent->conncheck_list) {
    g_slist_foreach (agent->conncheck_list, conn_check_free_item, NULL);
    g_slist_free (agent->conncheck_list),
      agent->conncheck_list = NULL;
    agent->conncheck_state = NICE_CHECKLIST_NOT_STARTED;
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
gboolean conn_check_prune_stream (NiceAgent *agent, guint stream_id)
{
  CandidateCheckPair *pair;
  GSList *i;

  for (i = agent->conncheck_list; i ; ) {
    pair = i->data;

    if (pair->stream_id == stream_id) {
      GSList *next = i->next;
      agent->conncheck_list = 
	g_slist_remove (agent->conncheck_list, pair);
      conn_check_free_item (pair, NULL);
      i = next;
      if (!agent->conncheck_list)
	break;
    }
    else
      i = i->next;
  }

  if (!agent->conncheck_list) {
    agent->conncheck_state = NICE_CHECKLIST_NOT_STARTED;
    conn_check_free (agent);
  }

  /* return FALSE if there was a memory allocation failure */
  if (agent->conncheck_list == NULL && i != NULL)
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
    g_snprintf (dest, dest_len, "%s:%s", pair->remote->username, pair->local->username);
    return TRUE;
  }

  stream = agent_find_stream (agent, pair->stream_id);
  if (stream) {
    g_snprintf (dest, dest_len, "%s:%s", stream->remote_ufrag, stream->local_ufrag);
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

  gboolean username_filled = 
     priv_create_check_username (agent, pair, agent->ufragtmp, NICE_STREAM_MAX_UNAME);
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
    g_debug ("STUN-CC REQ to '%s:%u', socket=%u, pair=%s (c-id:%u), tie=%llu, username='%s', password='%s', priority=%u.", 
	     tmpbuf,
	     ntohs(((struct sockaddr_in*)(&sockaddr))->sin_port), 
	     pair->local->sockptr->fileno,
	     pair->foundation, pair->component_id,
	     (unsigned long long)agent->tie_breaker,
	     agent->ufragtmp, password, priority);

  }
#endif

  if (cand_use) 
    pair->nominated = controlling;

  if (username_filled) {

    if (pair->stun_ctx)
      stun_bind_cancel (pair->stun_ctx);

    stun_conncheck_start (&pair->stun_ctx, pair->local->sockptr->fileno,
			  &sockaddr, sizeof (sockaddr),
			  agent->ufragtmp, password,
			  cand_use, controlling, priority,
			  agent->tie_breaker);

    timeout = stun_bind_timeout (pair->stun_ctx);
    /* note: convert from milli to microseconds for g_time_val_add() */
    g_get_current_time (&pair->next_tick);
    g_time_val_add (&pair->next_tick, timeout * 10);
    pair->traffic_after_tick = TRUE; /* for keepalive timer */
  }
    
  return 0;
}

/**
 * Updates the check list state.
 *
 * Implements parts of the algorithm described in 
 * ICE sect 8.1.2. "Updating States" (ID-17) that apply 
 * to the whole check list.
 */
static void priv_update_check_list_state (NiceAgent *agent, Stream *stream)
{
  GSList *i;
  /* note: emitting a signal might cause the client 
   *       to remove the stream, thus the component count
   *       must be fetched before entering the loop*/
  guint c, components = stream->n_components;
  

  /* note: iterate the conncheck list for each component separately */
  for (c = 0; c < components; c++) {
    guint not_failed = 0, checks = 0;
    for (i = agent->conncheck_list; i; i = i->next) {
      CandidateCheckPair *p = i->data;
      
      if (p->stream_id == stream->id &&
	  p->component_id == (c + 1)) {
	++checks;

	if (p->state != NICE_CHECK_FAILED)
	  ++not_failed;

	if ((p->state == NICE_CHECK_SUCCEEDED ||
	     p->state == NICE_CHECK_DISCOVERED) &&
	    p->nominated == TRUE)
	  break;
      }
    }

    /* note: all checks have failed */
    if (checks > 0 && not_failed == 0)
      agent_signal_component_state_change (agent, 
					   stream->id,
					   (c + 1), /* component-id */
					   NICE_COMPONENT_STATE_FAILED);
  }
}

/**
 * Implemented the pruning steps described in ICE sect 8.1.2
 * "Updating States" (ID-17) after a pair has been nominated.
 *
 * @see priv_update_check_list_state_for_component()
 */
static void priv_prune_pending_checks (NiceAgent *agent, guint component_id)
{
  GSList *i;

  /* step: cancel all FROZEN and WAITING pairs for the component */
  for (i = agent->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component_id) {
      if (p->state == NICE_CHECK_FROZEN ||
	  p->state == NICE_CHECK_WAITING)
	p->state = NICE_CHECK_CANCELLED;
      
      /* note: a SHOULD level req. in ICE 8.1.2. "Updating States" (ID-17) */
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
 * Updates the check list state for a stream component.
 *
 * Implements the algorithm described in ICE sect 8.1.2 
 * "Updating States" (ID-17) as it applies to checks of 
 * a certain component. If any there are any nominated pairs, 
 * ICE processing may be concluded, and component state is 
 * changed to READY.
 */
static void priv_update_check_list_state_for_component (NiceAgent *agent, Stream *stream, Component *component)
{
  GSList *i;
  guint succeeded = 0, nominated = 0;

  g_assert (component);

  /* step: search for at least one nominated pair */
  for (i = agent->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component->id) {
      if (p->state == NICE_CHECK_SUCCEEDED ||
	  p->state == NICE_CHECK_DISCOVERED) {
	++succeeded;
	if (p->nominated == TRUE) {
	  priv_prune_pending_checks (agent, p->component_id);
	  agent_signal_component_state_change (agent,
					       p->stream_id,
					       p->component_id,
					       NICE_COMPONENT_STATE_READY);
	}
      }
    }
  }
  
  g_debug ("conn.check list status: %u nominated, %u succeeded, c-id %u.", nominated, succeeded, component->id);

  priv_update_check_list_state (agent, stream);
}

/**
 * Changes the selected pair for the component if 'pair' is nominated
 * and has higher priority than the currently selected pair. See
 * ICE sect 11.1.1. "Procedures for Full Implementations" (ID-17).
 */ 
static gboolean priv_update_selected_pair (NiceAgent *agent, Component *component, CandidateCheckPair *pair)
{
  g_assert (component);
  g_assert (pair);
  if (pair->priority > component->selected_pair.priority) {
    g_debug ("changing SELECTED PAIR for component %u: %s:%s (prio:%lu).", 
	     component->id, pair->local->foundation, pair->remote->foundation, (long unsigned)pair->priority);
    component->selected_pair.local = pair->local;
    component->selected_pair.remote = pair->remote;
    component->selected_pair.priority = pair->priority;

    agent_signal_new_selected_pair (agent, pair->stream_id, component->id, pair->local->foundation, pair->remote->foundation);
  }

  return TRUE;
}

/**
 * Schedules a triggered check after a succesfully inbound 
 * connectivity check. Implements ICE sect 7.2.1.4 "Triggered Checks" (ID-17).
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

  for (i = agent->conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (p->component_id == component->id &&
	  p->remote == remote_cand &&
	  p->local->sockptr == local_socket) {

	g_debug ("Found a matching pair %p for triggered check.", p);
	
	if (p->state == NICE_CHECK_WAITING ||
	    p->state == NICE_CHECK_FROZEN)
	  priv_conn_check_initiate (agent, p);

	if (p->state == NICE_CHECK_IN_PROGRESS) {
	  /* XXX: according to ICE 7.2.1.4 "Triggered Checks" (ID-17),
	   * we should cancel the existing one, and send a new one...? :P */
	  g_debug ("Skipping triggered check, already in progress..");
	}
	else if (p->state == NICE_CHECK_SUCCEEDED ||
		 p->state == NICE_CHECK_DISCOVERED) {
	  g_debug ("Skipping triggered check, already completed.."); 
	  /* note: this is a bit unsure corner-case -- let's do the
	     same state update as for processing responses to our own checks */
	  priv_update_check_list_state_for_component (agent, stream, component);

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
    gboolean result = FALSE;
    NiceCandidate *local = NULL;

    for (i = component->local_candidates; i ; i = i->next) {
      local = i->data;
      if (local->sockptr == local_socket)
	break;
    }    
    if (local) {
      g_debug ("Adding a triggered check to conn.check list.");
      result = priv_add_new_check_pair (agent, stream->id, component, local, remote_cand, NICE_CHECK_WAITING, use_candidate);
    }
    else
      g_debug ("Didn't find a matching pair for triggered check (remote-cand=%p).", remote_cand);
  }

  return FALSE;
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
  for (i = agent->conncheck_list; i; i = i->next) {
    CandidateCheckPair *pair = i->data;
    /* XXX: hmm, how to figure out to which local candidate the 
     *      check was sent to? let's mark all matching pairs
     *      as nominated instead */
    if (pair->remote == remotecand) {
      g_debug ("marking pair %p (%s) as nominated", pair, pair->foundation);
      pair->nominated = TRUE;
      if (pair->state == NICE_CHECK_SUCCEEDED ||
	  pair->state == NICE_CHECK_DISCOVERED)
	priv_update_selected_pair (agent, component, pair);
      priv_update_check_list_state_for_component (agent, stream, component);
    }
  }
}

/**
 * Sends a reply to an succesfully received STUN connectivity 
 * check request. Implements parts of the ICE spec section 7.2 (STUN
 * Server Procedures).
 */
static void priv_reply_to_conn_check (NiceAgent *agent, Stream *stream, Component *component, NiceCandidate *cand, NiceUDPSocket *udp_socket, size_t  rbuf_len, uint8_t *rbuf, gboolean use_candidate)
{
#ifndef NDEBUG
  {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (&cand->addr, tmpbuf);
    g_debug ("STUN-CC RESP to '%s:%u', socket=%u, len=%u, cand=%p (c-id:%u), use-cand=%d.",
	     tmpbuf,
	     cand->addr.port,
	     udp_socket->fileno,
	     rbuf_len,
	     cand, component->id,
	     (int)use_candidate);
  }
#endif


  nice_udp_socket_send (udp_socket, &cand->addr, rbuf_len, (const gchar*)rbuf);
  
  if (use_candidate)
    priv_mark_pair_nominated (agent, stream, component, cand);

  /* note: upon succesful check, make the reserve check immediately */
  priv_schedule_triggered_check (agent, stream, component, udp_socket, cand, use_candidate);
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
    GSList *modified_list = g_slist_append (agent->conncheck_list, pair);
    if (modified_list) {
      agent->conncheck_list = modified_list;
      pair->agent = agent;
      pair->stream_id = stream_id;
      pair->component_id = component_id;;
      pair->local = local_cand;
      pair->remote = parent_pair->remote;
      pair->state = NICE_CHECK_DISCOVERED;
      g_snprintf (pair->foundation, NICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s", local_cand->foundation, parent_pair->remote->foundation);
      if (agent->controlling_mode == TRUE)
	pair->priority = nice_candidate_pair_priority (local_cand->priority, parent_pair->remote->priority);
      else
	pair->priority = nice_candidate_pair_priority (parent_pair->remote->priority, local_cand->priority);
      pair->nominated = FALSE;
      g_debug ("added a new peer-discovered pair with foundation of '%s'.", pair->foundation);
      return pair;
    }
  }

  return NULL;
}

/**
 * Tries to match STUN reply in 'buf' to an existing STUN connectivity
 * check transaction. If found, the reply is processed. Implements
 * section 7.1.2 "Processing the Response" of ICE spec (ID-17).
 * 
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_conn_check_request (NiceAgent *agent, Stream *stream, Component *component, NiceUDPSocket *sockptr, gchar *buf, guint len)
{
  struct sockaddr sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  GSList *i;
  ssize_t res;
  gboolean trans_found = FALSE;

  for (i = agent->conncheck_list; i && trans_found != TRUE; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->stun_ctx) {
      res = stun_bind_process (p->stun_ctx, buf, len, &sockaddr, &socklen); 
      g_debug ("stun_bind_process/conncheck for %p res %d (controlling=%d).", p, res, agent->controlling_mode);
      if (res == 0) {
	/* case: found a matching connectivity check request */

	CandidateCheckPair *ok_pair = p;

	gboolean local_cand_matches = FALSE;
	g_debug ("conncheck %p MATCHED.", p);
	p->stun_ctx = NULL;
	
	/* note: CONNECTED but not yet READY, see docs */
	
	/* step: handle the possible case of a peer-reflexive
	 *       candidate where the mapped-address in response does
	 *       not match any local candidate, see 7.1.2.2.1
	 *       "Discovering Peer Reflexive Candidates" ICE ID-17) */
	{
	  NiceAddress mapped;
	  GSList *j;
	  nice_address_set_from_sockaddr (&mapped, &sockaddr);

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
	    g_debug ("conncheck %p SUCCEEDED.", p);
	    priv_conn_check_unfreeze_related (agent, p);
	  }
	  else {
	    NiceCandidate *cand =
	      discovery_add_peer_reflexive_candidate (
  		agent,
		stream->id,
		component->id,
		&mapped,
		sockptr);
	    CandidateCheckPair *new_pair;

	    p->state = NICE_CHECK_FAILED;

	    /* step: add a new discovered pair (see ICE 7.1.2.2.2
	       "Constructing a Valid Pair" (ID-17)) */
	    new_pair = priv_add_peer_reflexive_pair (agent, stream->id, component->id, cand, p);
	    ok_pair = new_pair;

	    g_debug ("conncheck %p FAILED, %p DISCOVERED.", p, new_pair);
	  }
	}

	/* step: notify the client of a new component state (must be done
	 *       before the possible check list state update step */
	agent_signal_component_state_change (agent, 
					     stream->id,
					     component->id,
					     NICE_COMPONENT_STATE_CONNECTED);


	/* step: updating nominated flag (ICE 7.1.2.2.4 "Updating the
	   Nominated Flag" (ID-17) */
	if (ok_pair->nominated == TRUE) 
	  priv_update_selected_pair (agent, component, ok_pair);

	/* step: update pair states (ICE 7.1.2.2.3 "Updating pair
	   states" and 8.1.2 "Updating States", ID-17) */
	priv_update_check_list_state_for_component (agent, stream, component);

	trans_found = TRUE;
      }
      else if (res != EAGAIN) {
	/* case: STUN error, the check STUN context was freed */
	g_debug ("conncheck %p FAILED.", p);
	p->stun_ctx = NULL;
	trans_found = TRUE;
      }
      else {
	g_assert (res == EAGAIN);
	
	/* XXX: stun won't restart automatically, so cancel and
	 *   restart, should do this only for 487 errors (role conflict) */
	g_debug ("cancelling and restarting check for pair %p", p);

	stun_bind_cancel (p->stun_ctx), 
	  p->stun_ctx = NULL;
	p->state = NICE_CHECK_WAITING;
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
      g_debug ("stun_bind_process/disc for %p res %d.", d, res);
      if (res == 0) {
	/* case: succesful binding discovery, create a new local candidate */
	NiceAddress niceaddr;
	struct sockaddr_in *mapped = (struct sockaddr_in *)&sockaddr;
	niceaddr.type = NICE_ADDRESS_TYPE_IPV4;
	niceaddr.addr.addr_ipv4 = ntohl(mapped->sin_addr.s_addr);
	niceaddr.port = ntohs(mapped->sin_port);

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

static gboolean priv_verify_inbound_username (Stream *stream, const char *uname)
{
  const char *colon;

  if (uname == NULL)
    return FALSE;

  colon = strchr (uname, ':');
  if (colon == NULL)
    return FALSE;

  if (strncmp (uname, stream->local_ufrag, colon - uname) == 0)
    return TRUE;

  return FALSE;
}

/**
 * Recalculates priorities of all candidate pairs. This
 * is required after a conflict in ICE roles.
 */
static void priv_recalculate_pair_priorities (NiceAgent *agent)
{
  GSList *i;

  for (i = agent->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (agent->controlling_mode == TRUE)
      p->priority = nice_candidate_pair_priority (p->local->priority, p->remote->priority);
    else
      p->priority = nice_candidate_pair_priority (p->remote->priority, p->local->priority);
  }
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

  nice_address_copy_to_sockaddr (from, &sockaddr);

  /* note: contents of 'buf' already validated, so it is 
   *       a valid and fully received STUN message */

  g_debug ("inbound STUN packet for stream/component %u/%u:", stream->id, component->id);

  /* note: ICE  7.2. "STUN Server Procedures" (ID-17) */

  res = stun_conncheck_reply (rbuf, &rbuf_len, (const uint8_t*)buf, &sockaddr, sizeof (sockaddr), 
			      stream->local_password, &control, agent->tie_breaker);
  if (res == EACCES) {
    /* role conflict, change mode and regenarate reply */
    if (control != agent->controlling_mode) {
      g_debug ("Conflict in controller selection, switching to mode %d.", control);
      agent->controlling_mode = control;
      /* the pair priorities depend on the roles, so recalculation
       * is needed */
      priv_recalculate_pair_priorities (agent);
    }
  }

  if (res == 0 || res == EACCES) {
    /* case 1: valid incoming request, send a reply */
    
    GSList *i;
    bool use_candidate = 
      stun_conncheck_use_candidate ((const uint8_t*)buf);

    if (agent->controlling_mode) 
      use_candidate = TRUE;

    /* note: verify the USERNAME */
    if (stun_conncheck_username ((const uint8_t*)buf, agent->ufragtmp, NICE_STREAM_MAX_UNAME) == NULL) {
      g_debug ("No USERNAME attribute in incoming STUN request, ignoring.");
      return FALSE;
    }
     									   
    if (priv_verify_inbound_username (stream, agent->ufragtmp) != TRUE) {
      g_debug ("USERNAME does not match local streams, ignoring.");
      return FALSE;
    }

    if (stream->initial_binding_request_received != TRUE)
      agent_signal_initial_binding_request_received (agent, stream);

    for (i = component->remote_candidates; i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (nice_address_equal (from, &cand->addr)) {
	priv_reply_to_conn_check (agent, stream, component, cand, udp_socket, rbuf_len, rbuf, use_candidate);
	break;
      }
    }

    if (i == NULL) {
      NiceCandidate *candidate;
      g_debug ("No matching remote candidate for incoming check -> peer-reflexive candidate.");
      candidate = discovery_learn_remote_peer_reflexive_candidate (
	agent, stream, component, stun_conncheck_priority ((const uint8_t*)buf), from, udp_socket);
      if (candidate)
	priv_reply_to_conn_check (agent, stream, component, candidate, udp_socket, rbuf_len, rbuf, use_candidate);
    }
  }
  else if (res == EINVAL) {
    /* case 2: not a new request, might be a reply...  */

    gboolean trans_found = FALSE;

    /* note: ICE sect 7.1.2. "Processing the Response" (ID-17) */

    /* step: let's try to match the response to an existing check context */
    if (trans_found != TRUE)
      trans_found = 
	priv_map_reply_to_conn_check_request (agent, stream, component, udp_socket, buf, len);

    /* step: let's try to match the response to an existing discovery */
    if (trans_found != TRUE)
      trans_found = 
	priv_map_reply_to_discovery_request (agent, buf, len);

    if (trans_found != TRUE)
      g_debug ("Unable to match to an existing transaction, probably a keepalive.");
  }
  else {
    g_debug ("Invalid STUN packet, ignoring... %s", strerror(errno));
    return FALSE;
  }

  return TRUE;
}
