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

#include "debug.h"

#include "agent.h"
#include "agent-priv.h"
#include "conncheck.h"
#include "discovery.h"
#include "stun/usages/ice.h"
#include "stun/usages/bind.h"
#include "stun/usages/turn.h"

static void priv_update_check_list_failed_components (NiceAgent *agent, Stream *stream);
static void priv_prune_pending_checks (Stream *stream, guint component_id);
static gboolean priv_schedule_triggered_check (NiceAgent *agent, Stream *stream, Component *component, NiceSocket *local_socket, NiceCandidate *remote_cand, gboolean use_candidate);
static void priv_mark_pair_nominated (NiceAgent *agent, Stream *stream, Component *component, NiceCandidate *remotecand);

static int priv_timer_expired (GTimeVal *timer, GTimeVal *now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

static StunUsageIceCompatibility priv_agent_to_ice_compatibility (NiceAgent *agent) {
  return agent->compatibility == NICE_COMPATIBILITY_DRAFT19 ?
      STUN_USAGE_ICE_COMPATIBILITY_DRAFT19 :
      agent->compatibility == NICE_COMPATIBILITY_GOOGLE ?
      STUN_USAGE_ICE_COMPATIBILITY_GOOGLE :
      agent->compatibility == NICE_COMPATIBILITY_MSN ?
      STUN_USAGE_ICE_COMPATIBILITY_MSN : STUN_USAGE_ICE_COMPATIBILITY_DRAFT19;
}

static StunUsageTurnCompatibility priv_agent_to_turn_compatibility (NiceAgent *agent) {
  return agent->compatibility == NICE_COMPATIBILITY_DRAFT19 ?
      STUN_USAGE_TURN_COMPATIBILITY_DRAFT9 :
      agent->compatibility == NICE_COMPATIBILITY_GOOGLE ?
      STUN_USAGE_TURN_COMPATIBILITY_GOOGLE :
      agent->compatibility == NICE_COMPATIBILITY_MSN ?
      STUN_USAGE_TURN_COMPATIBILITY_MSN : STUN_USAGE_TURN_COMPATIBILITY_DRAFT9;
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
  nice_debug ("Agent %p : pair %p state IN_PROGRESS", agent, pair);
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
    nice_debug ("Agent %p : Pair %p with s/c-id %u/%u (%s) unfrozen.", agent, pair, pair->stream_id, pair->component_id, pair->foundation);
    pair->state = NICE_CHECK_WAITING;
    nice_debug ("Agent %p : pair %p state WAITING", agent, pair);
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
	nice_debug ("Agent %p : Unfreezing check %p (after succesful check %p).", agent, p, ok_check);
	p->state = NICE_CHECK_WAITING;
        nice_debug ("Agent %p : pair %p state WAITING", agent, p);
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
	    nice_debug ("Agent %p : Unfreezing check %p from stream %u (after succesful check %p).", agent, p, s->id, ok_check);
	    p->state = NICE_CHECK_WAITING;
            nice_debug ("Agent %p : pair %p state WAITING", agent, p);
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
      if (p->stun_message.buffer == NULL) {
	nice_debug ("Agent %p : STUN connectivity check was cancelled, marking as done.", agent);
	p->state = NICE_CHECK_FAILED;
        nice_debug ("Agent %p : pair %p state FAILED", agent, p);
      } else if (priv_timer_expired (&p->next_tick, now)) {
        int timeout = stun_timer_refresh (&p->timer);
        switch (timeout) {
          case -1:
            /* case: error, abort processing */
            nice_debug ("Agent %p : Retransmissions failed, giving up on connectivity check %p", agent, p);
            p->state = NICE_CHECK_FAILED;
            nice_debug ("Agent %p : pair %p state FAILED", agent, p);
            p->stun_message.buffer = NULL;
            p->stun_message.buffer_len = 0;
            break;
          case 0:
            {
              /* case: not ready, so schedule a new timeout */
              unsigned int timeout = stun_timer_remainder (&p->timer);
              nice_debug ("Agent %p :STUN transaction retransmitted (timeout %dms).",
                  agent, timeout);

              nice_socket_send (p->local->sockptr, &p->remote->addr,
                  stun_message_length (&p->stun_message),
                  (gchar *)p->stun_buffer);


              /* note: convert from milli to microseconds for g_time_val_add() */
              p->next_tick = *now;
              g_time_val_add (&p->next_tick, timeout * 1000);

              keep_timer_going = TRUE;
              p->traffic_after_tick = TRUE; /* for keepalive timer */
              break;
            }
          default:
            {
              /* note: convert from milli to microseconds for g_time_val_add() */
              p->next_tick = *now;
              g_time_val_add (&p->next_tick, timeout * 1000);

              keep_timer_going = TRUE;
              p->traffic_after_tick = TRUE; /* for keepalive timer */
              break;
            }
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
	    nice_debug ("Agent %p : restarting check %p as the nominated pair.", agent, p);
	    p->nominated = TRUE;
	    priv_conn_check_initiate (agent, p);	
	    break; /* move to the next component */
	  }
	}
      }
    }
  }
    {
    static int tick_counter = 0;
    if (tick_counter++ % 50 == 0 || keep_timer_going != TRUE)
      nice_debug ("Agent %p : timer(%p) tick #%u: %u frozen, %u in-progress, %u waiting, %u succeeded, %u nominated, %u waiting-for-nom.", agent, 
	       agent, tick_counter, frozen, s_inprogress, waiting, s_succeeded, s_nominated, s_waiting_for_nomination);
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
  } else {
    keep_timer_going = priv_conn_check_unfreeze_next (agent);
  }

  for (j = agent->streams; j; j = j->next) {
    Stream *stream = j->data;
    gboolean res =
      priv_conn_check_tick_stream (stream, agent, &now);
    if (res)
      keep_timer_going = res;
  }
  
  /* step: stop timer if no work left */
  if (keep_timer_going != TRUE) {
    nice_debug ("Agent %p : %s: stopping conncheck timer", agent, G_STRFUNC);
    for (i = agent->streams; i; i = i->next) {
      Stream *stream = i->data;
      priv_update_check_list_failed_components (agent, stream);
      stream->conncheck_state = NICE_CHECKLIST_COMPLETED;
    }
    conn_check_free (agent);
    /* XXX: what to signal, is all processing now really done? */
    nice_debug ("Agent %p : changing conncheck state to COMPLETED.", agent);
  }

  return keep_timer_going;
}

static gboolean priv_conn_check_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  gboolean ret;

  g_static_rec_mutex_lock (&agent->mutex);
  ret = priv_conn_check_tick_unlocked (pointer);
  g_static_rec_mutex_unlock (&agent->mutex);

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
  StunMessage msg;
  uint8_t buf[STUN_MAX_MESSAGE_SIZE];
  size_t buf_len;

  g_static_rec_mutex_lock (&agent->mutex);

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

	memset (&sockaddr, 0, sizeof (sockaddr));
	nice_address_copy_to_sockaddr (&p->remote->addr, &sockaddr);

        buf_len = stun_usage_bind_keepalive (&agent->stun_agent, &msg,
            buf, sizeof(buf));

        nice_socket_send (p->local->sockptr, &p->remote->addr, buf_len, (gchar *)buf);

	nice_debug ("Agent %p : stun_bind_keepalive for pair %p res %d.",
            agent, p, (int) buf_len);
	if (buf_len == 0)
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
	  nice_debug ("Agent %p : resending STUN-CC to keep the candidate alive (pair %p).", agent, p);
	  conn_check_send (agent, p);
	}
	p->traffic_after_tick = FALSE;
      }
    }
  }

  if (errors) {
    nice_debug ("Agent %p : %s: stopping keepalive timer", agent, G_STRFUNC);
    goto done;
  }

  ret = TRUE;

 done:
  g_static_rec_mutex_unlock (&agent->mutex);
  return ret;
}

static gboolean priv_turn_allocate_refresh_retransmissions_tick (gpointer pointer)
{
  CandidateRefresh *cand = (CandidateRefresh *) pointer;
  guint timeout;

  g_static_rec_mutex_lock (&cand->agent->mutex);

  g_source_destroy (cand->tick_source);
  g_source_unref (cand->tick_source);
  cand->tick_source = NULL;

  timeout = stun_timer_refresh (&cand->timer);
  switch (timeout) {
    case -1:
      /* Time out */
      refresh_cancel (cand);
      break;
    case 0:
      /* Retransmit */
      nice_socket_send (cand->nicesock, &cand->server,
          stun_message_length (&cand->stun_message), (gchar *)cand->stun_buffer);

      timeout = stun_timer_remainder (&cand->timer);
      cand->tick_source = agent_timeout_add_with_context (cand->agent, timeout,
          priv_turn_allocate_refresh_retransmissions_tick, cand);
      break;
    default:
      cand->tick_source = agent_timeout_add_with_context (cand->agent, timeout,
          priv_turn_allocate_refresh_retransmissions_tick, cand);
      break;
  }


  g_static_rec_mutex_unlock (&cand->agent->mutex);
  return FALSE;
}

static void priv_turn_allocate_refresh_tick_unlocked (CandidateRefresh *cand)
{
  uint8_t *username;
  size_t username_len;
  uint8_t *password;
  size_t password_len;
  size_t buffer_len = 0;

  username = (uint8_t *)cand->turn->username;
  username_len = (size_t) strlen (cand->turn->username);
  password = (uint8_t *)cand->turn->password;
  password_len = (size_t) strlen (cand->turn->password);

  if (cand->agent->compatibility == NICE_COMPATIBILITY_MSN) {
    username = g_base64_decode ((gchar *)username, &username_len);
    password = g_base64_decode ((gchar *)password, &password_len);
  }

  buffer_len = stun_usage_turn_create_refresh (&cand->stun_agent,
      &cand->stun_message,  cand->stun_buffer, sizeof(cand->stun_buffer),
      cand->stun_resp_msg.buffer == NULL ? NULL : &cand->stun_resp_msg, -1,
      username, username_len,
      password, password_len,
      priv_agent_to_turn_compatibility (cand->agent));

  if (cand->agent->compatibility == NICE_COMPATIBILITY_MSN) {
    g_free (cand->msn_turn_username);
    g_free (cand->msn_turn_password);
    cand->msn_turn_username = username;
    cand->msn_turn_password = password;
  }

  nice_debug ("Agent %p : Sending allocate Refresh %d", cand->agent, buffer_len);

  if (buffer_len > 0) {
    stun_timer_start (&cand->timer);

    /* send the refresh */
    nice_socket_send (cand->nicesock, &cand->server,
        buffer_len, (gchar *)cand->stun_buffer);

    if (cand->tick_source != NULL) {
      g_source_destroy (cand->tick_source);
      g_source_unref (cand->tick_source);
      cand->tick_source = NULL;
    }

    cand->tick_source = agent_timeout_add_with_context (cand->agent,
        stun_timer_remainder (&cand->timer),
        priv_turn_allocate_refresh_retransmissions_tick, cand);
  }

}


/**
 * Timer callback that handles refreshing TURN allocations
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_turn_allocate_refresh_tick (gpointer pointer)
{
  CandidateRefresh *cand = (CandidateRefresh *) pointer;

  g_static_rec_mutex_lock (&cand->agent->mutex);
  priv_turn_allocate_refresh_tick_unlocked (cand);
  g_static_rec_mutex_unlock (&cand->agent->mutex);

  return FALSE;
}


/**
 * Initiates the next pending connectivity check.
 * 
 * @return TRUE if a pending check was scheduled
 */
gboolean conn_check_schedule_next (NiceAgent *agent)
{
  gboolean res = priv_conn_check_unfreeze_next (agent);
  nice_debug ("Agent %p : priv_conn_check_unfreeze_next returned %d", agent, res);

  if (agent->discovery_unsched_items > 0)
    nice_debug ("Agent %p : WARN: starting conn checks before local candidate gathering is finished.", agent);

  if (res == TRUE) {
    /* step: call once imediately */
    res = priv_conn_check_tick_unlocked ((gpointer) agent);
    nice_debug ("Agent %p : priv_conn_check_tick_unlocked returned %d", agent, res);

    /* step: schedule timer if not running yet */
    if (res && agent->conncheck_timer_source == NULL) {
      agent->conncheck_timer_source = agent_timeout_add_with_context (agent, agent->timer_ta, priv_conn_check_tick, agent);
    }

    /* step: also start the keepalive timer */
    if (agent->keepalive_timer_source == NULL) {
      agent->keepalive_timer_source = agent_timeout_add_with_context (agent, NICE_AGENT_TIMER_TR_DEFAULT, priv_conn_keepalive_tick, agent);
    }

  }

  nice_debug ("Agent %p : conn_check_schedule_next returning %d", agent, res);
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
      nice_debug ("Agent %p : Updating check %p with stored early-icheck %p, %p/%u/%u (agent/stream/component).", agent, pair, icheck, agent, stream->id, component->id);
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
                icheck->local_socket,
                NULL, NULL);
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
    nice_debug ("Agent %p : changing SELECTED PAIR for component %u: %s:%s (prio:%lu).", agent, 
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
          ++nominated;
	  priv_prune_pending_checks (stream, p->component_id);
	  agent_signal_component_state_change (agent,
					       p->stream_id,
					       p->component_id,
					       NICE_COMPONENT_STATE_READY);
	}
      }
    }
  }
  
  nice_debug ("Agent %p : conn.check list status: %u nominated, %u succeeded, c-id %u.", agent, nominated, succeeded, component->id);
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
      nice_debug ("Agent %p : marking pair %p (%s) as nominated", agent, pair, pair->foundation);
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
      nice_debug ("Agent %p : creating new pair %p state %d", agent, pair, initial_state);
      pair->nominated = use_candidate;
      pair->controlling = agent->controlling_mode;
      
      /* note: for the first added check */
      if (!stream->conncheck_list)
	stream->conncheck_state = NICE_CHECKLIST_RUNNING;
      stream->conncheck_list = modified_list;

      result = TRUE;
      nice_debug ("Agent %p : added a new conncheck %p with foundation of '%s' to list %u.", agent, pair, pair->foundation, stream_id);

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
      if (agent->compatibility == NICE_COMPATIBILITY_DRAFT19 &&
          local->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE)
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
  pair->stun_message.buffer = NULL;
  pair->stun_message.buffer_len = 0;
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

  if (agent->conncheck_timer_source != NULL) {
    g_source_destroy (agent->conncheck_timer_source);
    g_source_unref (agent->conncheck_timer_source);
    agent->conncheck_timer_source = NULL;
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
static
size_t priv_gen_username (NiceAgent *agent, guint component_id,
    gchar *remote, gchar *local, uint8_t *dest, guint dest_len)
{
  guint len = 0;
  gsize remote_len = strlen (remote);
  gsize local_len = strlen (local);

  if (remote_len > 0 && local_len > 0) {
    if (agent->compatibility == NICE_COMPATIBILITY_DRAFT19 &&
        dest_len >= remote_len + local_len + 1) {
      memcpy (dest, remote, remote_len);
      len += remote_len;
      memcpy (dest + len, ":", 1);
      len++;
      memcpy (dest + len, local, local_len);
      len += local_len;
    } else if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE &&
        dest_len >= remote_len + local_len) {
      memcpy (dest, remote, remote_len);
      len += remote_len;
      memcpy (dest + len, local, local_len);
      len += local_len;
    } else if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
      gchar component_str[10];
      guchar *local_decoded = NULL;
      guchar *remote_decoded = NULL;
      gsize local_decoded_len;
      gsize remote_decoded_len;
      gsize total_len;
      int padding;

      g_snprintf (component_str, sizeof(component_str), "%d", component_id);
      local_decoded = g_base64_decode (local, &local_decoded_len);
      remote_decoded = g_base64_decode (remote, &remote_decoded_len);

      total_len = remote_decoded_len + local_decoded_len + 3 + 2*strlen (component_str);
      padding = 4 - (total_len % 4);

      if (dest_len >= total_len + padding) {
        guchar pad_char[1] = {0};
        int i;

        memcpy (dest, remote_decoded, remote_decoded_len);
        len += remote_decoded_len;
        memcpy (dest + len, ":", 1);
        len++;
        memcpy (dest + len, component_str, strlen (component_str));
        len += strlen (component_str);

        memcpy (dest + len, ":", 1);
        len++;

        memcpy (dest + len, local_decoded, local_decoded_len);
        len += local_decoded_len;
        memcpy (dest + len, ":", 1);
        len++;
        memcpy (dest + len, component_str, strlen (component_str));;
        len += strlen (component_str);

        for (i = 0; i < padding; i++) {
          memcpy (dest + len, pad_char, 1);
          len++;
        }

      }

      g_free (local_decoded);
      g_free (remote_decoded);
    }
  }

  return len;
}

/**
 * Fills 'dest' with a username string for use in an outbound connectivity
 * checks. No more than 'dest_len' characters (including terminating
 * NULL) is ever written to the 'dest'.
 */
static
size_t priv_create_username (NiceAgent *agent, Stream *stream,
    guint component_id, NiceCandidate *remote, NiceCandidate *local,
    uint8_t *dest, guint dest_len, gboolean inbound)
{
  gchar *local_username = NULL;
  gchar *remote_username = NULL;


  if (remote && remote->username) {
    remote_username = remote->username;
  }

  if (local && local->username) {
    local_username = local->username;
  }

  if (stream) {
    if (remote_username == NULL) {
      remote_username = stream->remote_ufrag;
    }
    if (local_username == NULL) {
      local_username = stream->local_ufrag;
    }
  }

  if (local_username && remote_username) {
    if (inbound) {
      return priv_gen_username (agent, component_id,
          local_username, remote_username, dest, dest_len);
    } else {
      return priv_gen_username (agent, component_id,
          remote_username, local_username, dest, dest_len);
    }
  }

  return 0;
}

/**
 * Returns a password string for use in an outbound connectivity
 * check.
 */
static
size_t priv_get_password (NiceAgent *agent, Stream *stream,
    NiceCandidate *remote, uint8_t **password)
{
  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE)
    return 0;

  if (remote && remote->password) {
    *password = (uint8_t *)remote->password;
    return strlen (remote->password);
  }

  if (stream) {
    *password = (uint8_t *)stream->remote_password;
    return strlen (stream->remote_password);
  }

  return 0;
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

  uint8_t uname[NICE_STREAM_MAX_UNAME];
  size_t uname_len =
      priv_create_username (agent, agent_find_stream (agent, pair->stream_id),
          pair->component_id, pair->remote, pair->local, uname, sizeof (uname), FALSE);
  uint8_t *password = NULL;
  size_t password_len = priv_get_password (agent,
      agent_find_stream (agent, pair->stream_id), pair->remote, &password);

  bool controlling = agent->controlling_mode;
 /* XXX: add API to support different nomination modes: */
  bool cand_use = controlling;
  size_t buffer_len;

  struct sockaddr sockaddr;
  unsigned int timeout;

  if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
    password = g_base64_decode ((gchar *) password, &password_len);
  }

  memset (&sockaddr, 0, sizeof (sockaddr)); 

  nice_address_copy_to_sockaddr (&pair->remote->addr, &sockaddr);

  {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (&pair->remote->addr, tmpbuf);
    nice_debug ("Agent %p : STUN-CC REQ to '%s:%u', socket=%u, pair=%s (c-id:%u), tie=%llu, username='%s' (%d), password='%s' (%d), priority=%u.", agent, 
	     tmpbuf,
	     ntohs(((struct sockaddr_in*)(&sockaddr))->sin_port), 
	     pair->local->sockptr->fileno,
	     pair->foundation, pair->component_id,
	     (unsigned long long)agent->tie_breaker,
        uname, uname_len, password, password_len, priority);

  }

  if (cand_use) 
    pair->nominated = controlling;

  if (uname_len > 0) {

    buffer_len = stun_usage_ice_conncheck_create (&agent->stun_agent,
        &pair->stun_message, pair->stun_buffer, sizeof(pair->stun_buffer),
        uname, uname_len, password, password_len,
        cand_use, controlling, priority,
        agent->tie_breaker,
        priv_agent_to_ice_compatibility (agent));

    nice_debug ("Agent %p: conncheck created %d - %p", agent, buffer_len, pair->stun_message.buffer);

    if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
      g_free (password);
    }

    stun_timer_start (&pair->timer);

    /* send the conncheck */
    nice_socket_send (pair->local->sockptr, &pair->remote->addr,
        buffer_len, (gchar *)pair->stun_buffer);

    timeout = stun_timer_remainder (&pair->timer);
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
	  p->state == NICE_CHECK_WAITING) {
	p->state = NICE_CHECK_CANCELLED;
        nice_debug ("Agent XXX : pair %p state CANCELED", p);
      }

      /* note: a SHOULD level req. in ICE 8.1.2. "Updating States" (ID-19) */
      if (p->state == NICE_CHECK_IN_PROGRESS) {
        p->stun_message.buffer = NULL;
        p->stun_message.buffer_len = 0;
	p->state = NICE_CHECK_CANCELLED;
        nice_debug ("Agent XXX : pair %p state CANCELED", p);
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
static gboolean priv_schedule_triggered_check (NiceAgent *agent, Stream *stream, Component *component, NiceSocket *local_socket, NiceCandidate *remote_cand, gboolean use_candidate)
{
  GSList *i;
  gboolean result = FALSE;

  for (i = stream->conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (p->component_id == component->id &&
	  p->remote == remote_cand &&
	  p->local->sockptr == local_socket) {

	nice_debug ("Agent %p : Found a matching pair %p for triggered check.", agent, p);
	
	if (p->state == NICE_CHECK_WAITING ||
	    p->state == NICE_CHECK_FROZEN)
	  priv_conn_check_initiate (agent, p);
        else if (p->state == NICE_CHECK_IN_PROGRESS) {
	  /* XXX: according to ICE 7.2.1.4 "Triggered Checks" (ID-19),
	   * we should cancel the existing one, and send a new one...? :P */
	  nice_debug ("Agent %p : Skipping triggered check, already in progress..", agent);
	}
	else if (p->state == NICE_CHECK_SUCCEEDED ||
		 p->state == NICE_CHECK_DISCOVERED) {
	  nice_debug ("Agent %p : Skipping triggered check, already completed..", agent); 
	  /* note: this is a bit unsure corner-case -- let's do the
	     same state update as for processing responses to our own checks */
	  priv_update_check_list_state_for_ready (agent, stream, component);

	  /* note: to take care of the controlling-controlling case in 
	   *       aggressive nomination mode, send a new triggered
	   *       check to nominate the pair */
	  if (agent->compatibility == NICE_COMPATIBILITY_DRAFT19 &&
              agent->controlling_mode)
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
      nice_debug ("Agent %p : Adding a triggered check to conn.check list (local=%p).", agent, local);
      result = priv_add_new_check_pair (agent, stream->id, component, local, remote_cand, NICE_CHECK_WAITING, use_candidate);
    }
    else
      nice_debug ("Agent %p : Didn't find a matching pair for triggered check (remote-cand=%p).", agent, remote_cand);
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
 * @param socket the socket over which the request came
 * @param rbuf_len length of STUN message to send
 * @param rbuf buffer containing the STUN message to send
 * @param use_candidate whether the request had USE_CANDIDATE attribute
 * 
 * @pre (rcand == NULL || nice_address_equal(rcand->addr, toaddr) == TRUE)
 */
static void priv_reply_to_conn_check (NiceAgent *agent, Stream *stream, Component *component, NiceCandidate *rcand, const NiceAddress *toaddr, NiceSocket *socket, size_t  rbuf_len, uint8_t *rbuf, gboolean use_candidate)
{
  g_assert (rcand == NULL || nice_address_equal(&rcand->addr, toaddr) == TRUE);

  {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (toaddr, tmpbuf);
    nice_debug ("Agent %p : STUN-CC RESP to '%s:%u', socket=%u, len=%u, cand=%p (c-id:%u), use-cand=%d.", agent,
	     tmpbuf,
	     nice_address_get_port (toaddr),
	     socket->fileno,
	     (unsigned)rbuf_len,
	     rcand, component->id,
	     (int)use_candidate);
  }

  nice_socket_send (socket, toaddr, rbuf_len, (const gchar*)rbuf);
  
  if (rcand) {
    /* note: upon succesful check, make the reserve check immediately */
    priv_schedule_triggered_check (agent, stream, component, socket, rcand, use_candidate);

    if (use_candidate)
      priv_mark_pair_nominated (agent, stream, component, rcand);
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
static int priv_store_pending_check (NiceAgent *agent, Component *component, const NiceAddress *from, NiceSocket *socket, uint32_t priority, gboolean use_candidate)
{
  IncomingCheck *icheck;
  nice_debug ("Agent %p : Storing pending check.", agent);

  if (component->incoming_checks &&
      g_slist_length (component->incoming_checks) >= 
      NICE_AGENT_MAX_REMOTE_CANDIDATES) {
    nice_debug ("Agent %p : WARN: unable to store information for early incoming check.", agent);
    return -1;
  }

  icheck = g_slice_new0 (IncomingCheck);
  if (icheck) {
    GSList *pending = g_slist_append (component->incoming_checks, icheck);
    if (pending) {
      component->incoming_checks = pending;
      icheck->from = *from;
      icheck->local_socket = socket;
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
      nice_debug ("Agent %p : pair %p state DISCOVERED", agent, pair);
      g_snprintf (pair->foundation, NICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s", local_cand->foundation, parent_pair->remote->foundation);
      if (agent->controlling_mode == TRUE)
	pair->priority = nice_candidate_pair_priority (local_cand->priority, parent_pair->priority);
      else
	pair->priority = nice_candidate_pair_priority (parent_pair->priority, local_cand->priority);
      pair->nominated = FALSE;
      pair->controlling = agent->controlling_mode;
      nice_debug ("Agent %p : added a new peer-discovered pair with foundation of '%s'.", agent, pair->foundation);
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
    nice_debug ("Agent %p : Role conflict, changing agent role to %d.", agent, control);
    agent->controlling_mode = control;
    /* the pair priorities depend on the roles, so recalculation
     * is needed */
    priv_recalculate_pair_priorities (agent);
  }
  else 
    nice_debug ("Agent %p : Role conflict, agent role already changed to %d.", agent, control);
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
static CandidateCheckPair *priv_process_response_check_for_peer_reflexive(NiceAgent *agent, Stream *stream, Component *component, CandidateCheckPair *p, NiceSocket *sockptr, struct sockaddr *mapped_sockaddr, NiceCandidate *local_candidate, NiceCandidate *remote_candidate)
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
    nice_debug ("Agent %p : conncheck %p SUCCEEDED.", agent, p);
    priv_conn_check_unfreeze_related (agent, stream, p);
  }
  else {
    NiceCandidate *cand =
      discovery_add_peer_reflexive_candidate (agent,
					      stream->id,
					      component->id,
					      &mapped,
					      sockptr,
					      local_candidate,
					      remote_candidate);
    p->state = NICE_CHECK_FAILED;
    nice_debug ("Agent %p : pair %p state FAILED", agent, p);
	    
    /* step: add a new discovered pair (see ICE 7.1.2.2.2
	       "Constructing a Valid Pair" (ID-19)) */
    new_pair = priv_add_peer_reflexive_pair (agent, stream->id, component->id, cand, p);
    nice_debug ("Agent %p : conncheck %p FAILED, %p DISCOVERED.", agent, p, new_pair);
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
static gboolean priv_map_reply_to_conn_check_request (NiceAgent *agent, Stream *stream, Component *component, NiceSocket *sockptr, const NiceAddress *from, NiceCandidate *local_candidate, NiceCandidate *remote_candidate, StunMessage *resp)
{
  struct sockaddr sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  GSList *i;
  StunUsageIceReturn res;
  gboolean trans_found = FALSE;
  stun_transid_t discovery_id;
  stun_transid_t response_id;
  stun_message_id (resp, response_id);

  for (i = stream->conncheck_list; i && trans_found != TRUE; i = i->next) {
    CandidateCheckPair *p = i->data;

    if (p->stun_message.buffer) {
      stun_message_id (&p->stun_message, discovery_id);

      if (memcmp (discovery_id, response_id, sizeof(stun_transid_t)) == 0) {
        res = stun_usage_ice_conncheck_process (resp, &sockaddr, &socklen,
            priv_agent_to_ice_compatibility (agent));
        nice_debug ("Agent %p : stun_bind_process/conncheck for %p res %d "
            "(controlling=%d).", agent, p, (int)res, agent->controlling_mode);


        if (res == STUN_USAGE_ICE_RETURN_SUCCESS) {
          /* case: found a matching connectivity check request */

          CandidateCheckPair *ok_pair = NULL;

          nice_debug ("Agent %p : conncheck %p MATCHED.", agent, p);
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;

          /* step: verify that response came from the same IP address we
           *       sent the original request to (see 7.1.2.1. "Failure
           *       Cases") */
          if (nice_address_equal (from, &p->remote->addr) != TRUE) {
            gchar tmpbuf[INET6_ADDRSTRLEN];
            gchar tmpbuf2[INET6_ADDRSTRLEN];

            p->state = NICE_CHECK_FAILED;
            nice_debug ("Agent %p : conncheck %p FAILED"
                " (mismatch of source address).", agent, p);
            nice_address_to_string (&p->remote->addr, tmpbuf);
            nice_address_to_string (from, tmpbuf2);
            nice_debug ("Agent %p : '%s:%u' != '%s:%u'", agent,
                tmpbuf, nice_address_get_port (&p->remote->addr),
                tmpbuf2, nice_address_get_port (from));

            trans_found = TRUE;
            break;
          }

          /* note: CONNECTED but not yet READY, see docs */

          /* step: handle the possible case of a peer-reflexive
           *       candidate where the mapped-address in response does
           *       not match any local candidate, see 7.1.2.2.1
           *       "Discovering Peer Reflexive Candidates" ICE ID-19) */

          ok_pair = priv_process_response_check_for_peer_reflexive(agent, stream, component,
              p, sockptr, &sockaddr, local_candidate, remote_candidate);

          if (!ok_pair)
            ok_pair = p;

          /* Do not step down to CONNECTED if we're already at state READY*/
          if (component->state != NICE_COMPONENT_STATE_READY) {
            /* step: notify the client of a new component state (must be done
             *       before the possible check list state update step */
            agent_signal_component_state_change (agent,
                stream->id, component->id, NICE_COMPONENT_STATE_CONNECTED);
          }


          /* step: updating nominated flag (ICE 7.1.2.2.4 "Updating the
             Nominated Flag" (ID-19) */
          if (ok_pair->nominated == TRUE) 
            priv_update_selected_pair (agent, component, ok_pair);

          /* step: update pair states (ICE 7.1.2.2.3 "Updating pair
             states" and 8.1.2 "Updating States", ID-19) */
          priv_update_check_list_state_for_ready (agent, stream, component);

          trans_found = TRUE;
        } else if (res == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT) {
          /* case: role conflict error, need to restart with new role */
          nice_debug ("Agent %p : conncheck %p ROLE CONFLICT, restarting", agent, p);
          /* note: our role might already have changed due to an
           * incoming request, but if not, change role now;
           * follows ICE 7.1.2.1 "Failure Cases" (ID-19) */
          priv_check_for_role_conflict (agent, !p->controlling);

          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          p->state = NICE_CHECK_WAITING;
          nice_debug ("Agent %p : pair %p state WAITING", agent, p);
          trans_found = TRUE;
        } else if (res == STUN_USAGE_ICE_RETURN_ERROR) {
          /* case: STUN error, the check STUN context was freed */
          nice_debug ("Agent %p : conncheck %p FAILED.", agent, p);
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          trans_found = TRUE;
        }
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
static gboolean priv_map_reply_to_discovery_request (NiceAgent *agent, StunMessage *resp)
{
  struct sockaddr sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  struct sockaddr alternate;
  socklen_t alternatelen = sizeof (sockaddr);
  GSList *i;
  StunUsageBindReturn res;
  gboolean trans_found = FALSE;
  stun_transid_t discovery_id;
  stun_transid_t response_id;
  stun_message_id (resp, response_id);

  for (i = agent->discovery_list; i && trans_found != TRUE; i = i->next) {
    CandidateDiscovery *d = i->data;

    if (d->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
        d->stun_message.buffer) {
      stun_message_id (&d->stun_message, discovery_id);

      if (memcmp (discovery_id, response_id, sizeof(stun_transid_t)) == 0) {
        res = stun_usage_bind_process (resp, &sockaddr, &socklen,
            &alternate, &alternatelen);
        nice_debug ("Agent %p : stun_bind_process/disc for %p res %d.",
            agent, d, (int)res);

        if (res == STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER) {
          /* handle alternate server */
          NiceAddress niceaddr;
          nice_address_set_from_sockaddr (&niceaddr, &alternate);
          d->server = niceaddr;

          d->pending = FALSE;
        } else if (res == STUN_USAGE_BIND_RETURN_SUCCESS) {
          /* case: succesful binding discovery, create a new local candidate */
          NiceAddress niceaddr;
          nice_address_set_from_sockaddr (&niceaddr, &sockaddr);

          discovery_add_server_reflexive_candidate (
              d->agent,
              d->stream->id,
              d->component->id,
              &niceaddr,
              d->nicesock);

          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = TRUE;
          trans_found = TRUE;
        } else if (res == STUN_USAGE_BIND_RETURN_ERROR) {
          /* case: STUN error, the check STUN context was freed */
          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = TRUE;
          trans_found = TRUE;
        }
      }
    }
  }

  return trans_found;
}


static CandidateRefresh *
priv_add_new_turn_refresh (CandidateDiscovery *cdisco, NiceCandidate *relay_cand,
    guint lifetime)
{
  CandidateRefresh *cand;
  NiceAgent *agent = cdisco->agent;
  GSList *modified_list;

  cand = g_slice_new0 (CandidateRefresh);
  if (cand) {
    modified_list = g_slist_append (agent->refresh_list, cand);

    if (modified_list) {
      cand->nicesock = cdisco->nicesock;
      cand->relay_socket = relay_cand->sockptr;
      cand->server = cdisco->server;
      cand->turn = cdisco->turn;
      cand->stream = cdisco->stream;
      cand->component = cdisco->component;
      cand->agent = cdisco->agent;
      memcpy (&cand->stun_agent, &cdisco->stun_agent, sizeof(StunAgent));
      nice_debug ("Agent %p : Adding new refresh candidate %p with timeout %d",
          agent, cand, (lifetime - 60) * 1000);
      agent->refresh_list = modified_list;

      /* step: also start the keepalive timer */
      /* refresh should be sent 1 minute before it expires */
      cand->timer_source =
          agent_timeout_add_with_context (agent, (lifetime - 60) * 1000,
              priv_turn_allocate_refresh_tick, cand);

      nice_debug ("timer source is : %d", cand->timer_source);
    }
  }

  return cand;
}

/**
 * Tries to match STUN reply in 'buf' to an existing STUN discovery
 * transaction. If found, a reply is sent.
 * 
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_relay_request (NiceAgent *agent, StunMessage *resp)
{
  struct sockaddr sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  struct sockaddr alternate;
  socklen_t alternatelen = sizeof (alternate);
  struct sockaddr relayaddr;
  socklen_t relayaddrlen = sizeof (relayaddr);
  uint32_t lifetime;
  uint32_t bandwidth;
  GSList *i;
  StunUsageTurnReturn res;
  gboolean trans_found = FALSE;
  stun_transid_t discovery_id;
  stun_transid_t response_id;
  stun_message_id (resp, response_id);

  for (i = agent->discovery_list; i && trans_found != TRUE; i = i->next) {
    CandidateDiscovery *d = i->data;

    if (d->type == NICE_CANDIDATE_TYPE_RELAYED &&
        d->stun_message.buffer) {
      stun_message_id (&d->stun_message, discovery_id);

      if (memcmp (discovery_id, response_id, sizeof(stun_transid_t)) == 0) {
        res = stun_usage_turn_process (resp,
            &relayaddr, &relayaddrlen, &sockaddr, &socklen, &alternate, &alternatelen,
            &bandwidth, &lifetime, priv_agent_to_turn_compatibility (agent));
        nice_debug ("Agent %p : stun_turn_process/disc for %p res %d.",
            agent, d, (int)res);

        if (res == STUN_USAGE_TURN_RETURN_ALTERNATE_SERVER) {
          /* handle alternate server */
          nice_address_set_from_sockaddr (&d->server, &alternate);
          nice_address_set_from_sockaddr (&d->turn->server, &alternate);

          d->pending = FALSE;
        } else if (res == STUN_USAGE_TURN_RETURN_RELAY_SUCCESS ||
                   res == STUN_USAGE_TURN_RETURN_MAPPED_SUCCESS) {
          /* case: succesful allocate, create a new local candidate */
          NiceAddress niceaddr;
          NiceCandidate *relay_cand;

          /* We also received our mapped address */
          if (res == STUN_USAGE_TURN_RETURN_MAPPED_SUCCESS) {
            nice_address_set_from_sockaddr (&niceaddr, &sockaddr);

            discovery_add_server_reflexive_candidate (
                d->agent,
                d->stream->id,
                d->component->id,
                &niceaddr,
                d->nicesock);
          }

          nice_address_set_from_sockaddr (&niceaddr, &relayaddr);
          relay_cand = discovery_add_relay_candidate (
             d->agent,
             d->stream->id,
             d->component->id,
             &niceaddr,
             d->nicesock,
             d->turn);

          priv_add_new_turn_refresh (d, relay_cand, lifetime);


          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = TRUE;
          trans_found = TRUE;
        } else if (res == STUN_USAGE_TURN_RETURN_ERROR) {
          int code = -1;
          uint8_t *sent_realm = NULL;
          uint8_t *recv_realm = NULL;
          uint16_t sent_realm_len = 0;
          uint16_t recv_realm_len = 0;

          sent_realm = (uint8_t *) stun_message_find (&d->stun_message,
              STUN_ATTRIBUTE_REALM, &sent_realm_len);
          recv_realm = (uint8_t *) stun_message_find (resp,
              STUN_ATTRIBUTE_REALM, &recv_realm_len);

          /* check for unauthorized error response */
          if (agent->compatibility == NICE_COMPATIBILITY_DRAFT19 &&
              stun_message_get_class (resp) == STUN_ERROR &&
              stun_message_find_error (resp, &code) == 0 &&
              recv_realm != NULL && recv_realm_len > 0) {

            if (code == 438 ||
                (code == 401 &&
                    !(recv_realm_len == sent_realm_len &&
                        sent_realm != NULL &&
                        memcmp (sent_realm, recv_realm, sent_realm_len) == 0))) {
              d->stun_resp_msg = *resp;
              memcpy (d->stun_resp_buffer, resp->buffer,
                  stun_message_length (resp));
              d->stun_resp_msg.buffer = d->stun_resp_buffer;
              d->stun_resp_msg.buffer_len = sizeof(d->stun_resp_buffer);
              d->pending = FALSE;
            } else {
              /* case: a real unauthorized error */
              d->stun_message.buffer = NULL;
              d->stun_message.buffer_len = 0;
              d->done = TRUE;
            }
          } else {
            /* case: STUN error, the check STUN context was freed */
            d->stun_message.buffer = NULL;
            d->stun_message.buffer_len = 0;
            d->done = TRUE;
          }
          trans_found = TRUE;
        }
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
static gboolean priv_map_reply_to_relay_refresh (NiceAgent *agent, StunMessage *resp)
{
  uint32_t lifetime;
  GSList *i;
  StunUsageTurnReturn res;
  gboolean trans_found = FALSE;
  stun_transid_t refresh_id;
  stun_transid_t response_id;
  stun_message_id (resp, response_id);

  for (i = agent->refresh_list; i && trans_found != TRUE; i = i->next) {
    CandidateRefresh *cand = i->data;

    if (cand->stun_message.buffer) {
      stun_message_id (&cand->stun_message, refresh_id);

      if (memcmp (refresh_id, response_id, sizeof(stun_transid_t)) == 0) {
        res = stun_usage_turn_refresh_process (resp,
            &lifetime, priv_agent_to_turn_compatibility (cand->agent));
        nice_debug ("Agent %p : stun_turn_refresh_process for %p res %d.",
            agent, cand, (int)res);
        if (res == STUN_USAGE_TURN_RETURN_RELAY_SUCCESS) {
          /* refresh should be sent 1 minute before it expires */
          cand->timer_source =
              agent_timeout_add_with_context (cand->agent, (lifetime - 60) * 1000,
              priv_turn_allocate_refresh_tick, cand);

          g_source_destroy (cand->tick_source);
          g_source_unref (cand->tick_source);
          cand->tick_source = NULL;
        } else if (res == STUN_USAGE_TURN_RETURN_ERROR) {
          int code = -1;
          uint8_t *sent_realm = NULL;
          uint8_t *recv_realm = NULL;
          uint16_t sent_realm_len = 0;
          uint16_t recv_realm_len = 0;

          sent_realm = (uint8_t *) stun_message_find (&cand->stun_message,
              STUN_ATTRIBUTE_REALM, &sent_realm_len);
          recv_realm = (uint8_t *) stun_message_find (resp,
              STUN_ATTRIBUTE_REALM, &recv_realm_len);

          /* check for unauthorized error response */
          if (cand->agent->compatibility == NICE_COMPATIBILITY_DRAFT19 &&
              stun_message_get_class (resp) == STUN_ERROR &&
              stun_message_find_error (resp, &code) == 0 &&
              recv_realm != NULL && recv_realm_len > 0) {

            if (code == 438 ||
                (code == 401 &&
                    !(recv_realm_len == sent_realm_len &&
                        sent_realm != NULL &&
                        memcmp (sent_realm, recv_realm, sent_realm_len) == 0))) {
              cand->stun_resp_msg = *resp;
              memcpy (cand->stun_resp_buffer, resp->buffer,
                  stun_message_length (resp));
              cand->stun_resp_msg.buffer = cand->stun_resp_buffer;
              cand->stun_resp_msg.buffer_len = sizeof(cand->stun_resp_buffer);
              priv_turn_allocate_refresh_tick_unlocked (cand);
            } else {
              /* case: a real unauthorized error */
              refresh_cancel (cand);
            }
          } else {
            /* case: STUN error, the check STUN context was freed */
              refresh_cancel (cand);
          }
          trans_found = TRUE;
        }
      }
    }
  }

  return trans_found;
}


typedef struct {
  NiceAgent *agent;
  Stream *stream;
  Component *component;
  uint8_t *password;
} conncheck_validater_data;

static bool conncheck_stun_validater (StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data)
{
  conncheck_validater_data *data = (conncheck_validater_data*) user_data;
  GSList *i;
  uint8_t uname[NICE_STREAM_MAX_UNAME];
  guint uname_len = 0;

  for (i = data->component->local_candidates; i; i = i->next) {
    NiceCandidate *cand = i->data;
    gchar *ufrag = NULL;
    gsize ufrag_len;

    if (cand->username)
      ufrag = cand->username;
    else if (data->stream)
      ufrag = data->stream->local_ufrag;
    ufrag_len = strlen (ufrag);

    if (data->agent->compatibility == NICE_COMPATIBILITY_MSN)
      ufrag = (gchar *)g_base64_decode (ufrag, &ufrag_len);

    if (ufrag_len <= NICE_STREAM_MAX_UNAME) {
      memcpy (uname, ufrag, ufrag_len);
      uname_len = ufrag_len;
    }

    if (data->agent->compatibility == NICE_COMPATIBILITY_MSN)
      g_free (ufrag);

    stun_debug ("Comparing username '");
    stun_debug_bytes (username, username_len);
    stun_debug ("' (%d) with '", username_len);
    stun_debug_bytes (uname, uname_len);
    stun_debug ("' (%d) : %d\n",
        uname, memcmp (username, uname, uname_len));
    if (uname_len > 0 && username_len >= uname_len &&
        memcmp (username, uname, uname_len) == 0) {
      gchar *pass = NULL;

      if (cand->password)
        pass = cand->password;
      else
        pass = data->stream->local_password;

      *password = (uint8_t *) pass;
      *password_len = strlen (pass);

      if (data->agent->compatibility == NICE_COMPATIBILITY_MSN) {
        data->password = g_base64_decode (pass, password_len);
        *password = data->password;
      }

      stun_debug ("Found valid username, returning password: '%s'\n", *password);
      return true;
    }
  }

  return false;
}


/**
 * Processing an incoming STUN message.
 *
 * @param agent self pointer
 * @param stream stream the packet is related to
 * @param component component the packet is related to
 * @param socket socket from which the packet was received
 * @param from address of the sender
 * @param buf message contents
 * @param buf message length
 *
 * @pre contents of 'buf' is a STUN message
 *
 * @return XXX (what FALSE means exactly?)
 */
gboolean conn_check_handle_inbound_stun (NiceAgent *agent, Stream *stream,
    Component *component, NiceSocket *socket, const NiceAddress *from,
    gchar *buf, guint len)
{
  struct sockaddr sockaddr;
  uint8_t rbuf[MAX_STUN_DATAGRAM_PAYLOAD];
  ssize_t res;
  size_t rbuf_len = sizeof (rbuf);
  bool control = agent->controlling_mode;
  uint8_t uname[NICE_STREAM_MAX_UNAME];
  guint uname_len;
  uint8_t *username;
  uint16_t username_len;
  StunMessage req;
  StunMessage msg;
  StunValidationStatus valid;
  conncheck_validater_data validater_data = {agent, stream, component, NULL};
  GSList *i, *j;
  NiceCandidate *remote_candidate = NULL;
  NiceCandidate *remote_candidate2 = NULL;
  NiceCandidate *local_candidate = NULL;
  gboolean turn_msg = FALSE;

  nice_address_copy_to_sockaddr (from, &sockaddr);

  /* note: contents of 'buf' already validated, so it is
   *       a valid and fully received STUN message */

#ifndef NDEBUG
  {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (from, tmpbuf);
    nice_debug ("Agent %p: inbound STUN packet for %u/%u (stream/component) from [%s]:%u (%u octets) :",
        agent, stream->id, component->id, tmpbuf, nice_address_get_port (from), len);
  }
#endif

  /* note: ICE  7.2. "STUN Server Procedures" (ID-19) */

  valid = stun_agent_validate (&agent->stun_agent, &req,
      (uint8_t *) buf, len, conncheck_stun_validater, &validater_data);

  /* Check for relay candidates stun agents */
  if (valid == STUN_VALIDATION_BAD_REQUEST ||
      valid == STUN_VALIDATION_UNMATCHED_RESPONSE) {
    for (i = agent->discovery_list; i; i = i->next) {
      CandidateDiscovery *d = i->data;
      if (d->type == NICE_CANDIDATE_TYPE_RELAYED &&
          d->stream == stream && d->component == component &&
          d->nicesock == socket) {
        valid = stun_agent_validate (&d->stun_agent, &req,
            (uint8_t *) buf, len, conncheck_stun_validater, &validater_data);

        if (valid == STUN_VALIDATION_UNMATCHED_RESPONSE)
          continue;

        turn_msg = TRUE;
        break;
      }
    }
  }
  /* Check for relay candidates stun agents */
  if (valid == STUN_VALIDATION_BAD_REQUEST ||
      valid == STUN_VALIDATION_UNMATCHED_RESPONSE) {
    for (i = agent->refresh_list; i; i = i->next) {
      CandidateRefresh *r = i->data;
      nice_debug ("Comparing %p to %p, %p to %p and %p and %p to %p", r->stream,
          stream, r->component, component, r->nicesock, r->relay_socket, socket);
      if (r->stream == stream && r->component == component &&
          (r->nicesock == socket || r->relay_socket == socket)) {
        valid = stun_agent_validate (&r->stun_agent, &req,
            (uint8_t *) buf, len, conncheck_stun_validater, &validater_data);
        nice_debug ("Validating gave %d", valid);
        if (valid == STUN_VALIDATION_UNMATCHED_RESPONSE)
          continue;
        turn_msg = TRUE;
        break;
      }
    }
  }


  if (validater_data.password)
    g_free (validater_data.password);

  if (valid == STUN_VALIDATION_NOT_STUN ||
      valid == STUN_VALIDATION_INCOMPLETE_STUN ||
      valid == STUN_VALIDATION_BAD_REQUEST)
  {
    nice_debug ("Agent %p : Incorrectly multiplexed STUN message ignored.",
        agent);
    return FALSE;
  }

  if (valid == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE) {
    nice_debug ("Agent %p : Unknown mandatory attributes in message.", agent);
    rbuf_len = stun_agent_build_unknown_attributes_error (&agent->stun_agent,
        &msg, rbuf, rbuf_len, &req);
    if (len == 0)
      return FALSE;

    if (agent->compatibility != NICE_COMPATIBILITY_MSN) {
      nice_socket_send (socket, from, rbuf_len, (const gchar*)rbuf);
    }
    return TRUE;
  }

  if (valid == STUN_VALIDATION_UNAUTHORIZED) {
    nice_debug ("Agent %p : Integrity check failed.", agent);

    if (stun_agent_init_error (&agent->stun_agent, &msg, rbuf, rbuf_len,
            &req, STUN_ERROR_UNAUTHORIZED)) {
      rbuf_len = stun_agent_finish_message (&agent->stun_agent, &msg, NULL, 0);
      if (rbuf_len > 0 && agent->compatibility != NICE_COMPATIBILITY_MSN)
        nice_socket_send (socket, from, rbuf_len, (const gchar*)rbuf);
    }
    return TRUE;
  }
  if (valid == STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST) {
    nice_debug ("Agent %p : Integrity check failed.", agent);
    if (stun_agent_init_error (&agent->stun_agent, &msg, rbuf, rbuf_len,
            &req, STUN_ERROR_BAD_REQUEST)) {
      rbuf_len = stun_agent_finish_message (&agent->stun_agent, &msg, NULL, 0);
      if (rbuf_len > 0 && agent->compatibility != NICE_COMPATIBILITY_MSN)
        nice_socket_send (socket, from, rbuf_len, (const gchar*)rbuf);
    }
    return TRUE;
  }

  username = (uint8_t *) stun_message_find (&req, STUN_ATTRIBUTE_USERNAME,
					    &username_len);

  for (i = component->remote_candidates; i; i = i->next) {
    NiceCandidate *cand = i->data;
    if (nice_address_equal (from, &cand->addr)) {
      remote_candidate = cand;
      break;
    }
  }

  /* We need to find which local candidate was used */
  for (i = component->remote_candidates; i; i = i->next) {
    for (j = component->local_candidates; j; j = j->next) {
      gboolean inbound = TRUE;
      NiceCandidate *rcand = i->data;
      NiceCandidate *lcand = j->data;

      /* If we receive a response, then the username is local:remote */
      if (agent->compatibility != NICE_COMPATIBILITY_MSN) {
        if (stun_message_get_class (&req) == STUN_REQUEST ||
            stun_message_get_class (&req) == STUN_INDICATION) {
          inbound = TRUE;
        } else {
          inbound = FALSE;
        }
      }
      uname_len = priv_create_username (agent, stream,
          component->id,  rcand, lcand,
          uname, sizeof (uname), inbound);

      if (username &&
          uname_len == username_len &&
          memcmp (uname, username, username_len) == 0) {
        local_candidate = lcand;
        remote_candidate2 = rcand;
        break;
      }
    }
  }

  if (agent->compatibility == NICE_COMPATIBILITY_GOOGLE &&
      local_candidate == NULL &&
      turn_msg == FALSE) {
    /* if we couldn't match the username and the stun agent has
       IGNORE_CREDENTIALS then we have an integrity check failing */
    nice_debug ("Agent %p : Username check failed.", agent);
    if (stun_agent_init_error (&agent->stun_agent, &msg, rbuf, rbuf_len,
			       &req, STUN_ERROR_UNAUTHORIZED)) {
      rbuf_len = stun_agent_finish_message (&agent->stun_agent, &msg, NULL, 0);
      if (rbuf_len > 0&& agent->compatibility != NICE_COMPATIBILITY_MSN)
	nice_socket_send (socket, from, rbuf_len, (const gchar*)rbuf);
    }
    return TRUE;
  }

  if (valid != STUN_VALIDATION_SUCCESS) {
    nice_debug ("Agent %p : STUN message is unsuccessfull %d, ignoring", agent, valid);
    return FALSE;
  }


  if (stun_message_get_class (&req) == STUN_REQUEST) {
    if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
      username = (uint8_t *) stun_message_find (&req,
          STUN_ATTRIBUTE_USERNAME, &username_len);
      uname_len = priv_create_username (agent, stream,
          component->id,  remote_candidate2, local_candidate,
          uname, sizeof (uname), FALSE);
      memcpy (username, uname, username_len);
      if (remote_candidate2) {
        req.key = g_base64_decode ((gchar *) remote_candidate2->password,
            &req.key_len);
      } else {
        req.key = NULL;
        req.key_len = 0;
      }
    }

    rbuf_len = sizeof (rbuf);
    res = stun_usage_ice_conncheck_create_reply (&agent->stun_agent, &req,
        &msg, rbuf, &rbuf_len, &sockaddr, sizeof (sockaddr),
        &control, agent->tie_breaker,
        priv_agent_to_ice_compatibility (agent));

    if (agent->compatibility == NICE_COMPATIBILITY_MSN) {
      g_free (req.key);
    }

    if (res == EACCES)
      priv_check_for_role_conflict (agent, control);

    if (res == 0 || res == EACCES) {
      /* case 1: valid incoming request, send a reply/error */
      bool use_candidate =
          stun_usage_ice_conncheck_use_candidate (&req);
      uint32_t priority = stun_usage_ice_conncheck_priority (&req);

      if (agent->controlling_mode ||
          agent->compatibility == NICE_COMPATIBILITY_GOOGLE ||
          agent->compatibility == NICE_COMPATIBILITY_MSN)
        use_candidate = TRUE;

      if (stream->initial_binding_request_received != TRUE)
        agent_signal_initial_binding_request_received (agent, stream);

      if (component->remote_candidates && remote_candidate == NULL) {
	nice_debug ("Agent %p : No matching remote candidate for incoming check ->"
            "peer-reflexive candidate.", agent);
	remote_candidate = discovery_learn_remote_peer_reflexive_candidate (
            agent, stream, component, priority, from, socket,
            local_candidate, remote_candidate2);
      }

      priv_reply_to_conn_check (agent, stream, component, remote_candidate,
          from, socket, rbuf_len, rbuf, use_candidate);

      if (component->remote_candidates == NULL) {
        /* case: We've got a valid binding request to a local candidate
         *       but we do not yet know remote credentials nor
         *       candidates. As per sect 7.2 of ICE (ID-19), we send a reply
         *       immediately but postpone all other processing until
         *       we get information about the remote candidates */

        /* step: send a reply immediately but postpone other processing */
        priv_store_pending_check (agent, component, from, socket,
            priority, use_candidate);
      }
    } else {
      nice_debug ("Agent %p : Invalid STUN packet, ignoring... %s",
          agent, strerror(errno));
      return FALSE;
    }
  } else {
      /* case 2: not a new request, might be a reply...  */
      gboolean trans_found = FALSE;

      /* note: ICE sect 7.1.2. "Processing the Response" (ID-19) */

      /* step: let's try to match the response to an existing check context */
      if (trans_found != TRUE)
        trans_found = priv_map_reply_to_conn_check_request (agent, stream,
	    component, socket, from, local_candidate, remote_candidate, &req);

      /* step: let's try to match the response to an existing discovery */
      if (trans_found != TRUE)
        trans_found = priv_map_reply_to_discovery_request (agent, &req);

      /* step: let's try to match the response to an existing turn allocate */
      if (trans_found != TRUE)
        trans_found = priv_map_reply_to_relay_request (agent, &req);

      /* step: let's try to match the response to an existing turn refresh */
      if (trans_found != TRUE)
        trans_found = priv_map_reply_to_relay_refresh (agent, &req);

      if (trans_found != TRUE)
        nice_debug ("Agent %p : Unable to match to an existing transaction, "
            "probably a keepalive.", agent);
  }

  return TRUE;
}
