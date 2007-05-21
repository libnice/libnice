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

#include <errno.h>
#include <string.h>

#include <glib.h>

#ifndef _BSD_SOURCE
#error "timercmp() macros needed"
#endif
#include <sys/time.h> /* timercmp() macro, BSD */

#include "agent.h"
#include "agent-priv.h"
#include "conncheck.h"
#include "discovery.h"
#include "stun.h"


static void priv_update_check_list_state (NiceAgent *agent, Stream *stream);

/**
 * Finds the next connectivity check in WAITING state.
 */
static CandidateCheckPair *priv_conn_check_find_next_waiting (GSList *conn_check_list)
{
  GSList *i;

  /* XXX: should return the highest priority check on the
   *      waiting list! */

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
  g_get_current_time (&pair->next_tick);
  g_time_val_add (&pair->next_tick, 6000); /* XXX: 600msec */
  pair->state = NICE_CHECK_IN_PROGRESS;
  conn_check_send (agent, pair);
  return TRUE;
}

/**
 * Unfreezes the next connectivity check in the list. Follows the
 * algorithm defined in 5.7.4 of the ICE spec (-15).
 * 
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static gboolean priv_conn_check_unfreeze_next (GSList *conncheck_list)
{
  CandidateCheckPair *pair = NULL;
  guint64 max_priority = 0;
  GSList *i;
  int c;

  for (c = NICE_COMPONENT_TYPE_RTP; (pair == NULL) && c < NICE_COMPONENT_TYPE_RTCP; c++) {
    for (i = conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (p->state == NICE_CHECK_FROZEN &&
	  p->priority > max_priority) {
	max_priority = p->priority;
	pair = p;
      }
    }
  }
  
  if (pair) {
    g_debug ("Pair %p (%s) unfrozen.", pair, pair->foundation);
    pair->state = NICE_CHECK_WAITING;
    return TRUE;
  }

  return FALSE;
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
  pair = priv_conn_check_find_next_waiting (agent->conncheck_list);

#ifdef DEBUG
  {
    static int tick_counter = 0;
    if (++tick_counter % 20 == 0)
      g_debug ("conncheck tick #%d with list %p (1)", tick_counter, pair);
  }
#endif

  if (!pair) {
    gboolean c = priv_conn_check_unfreeze_next (agent->conncheck_list);
    if (c == TRUE) {
      pair = priv_conn_check_find_next_waiting (agent->conncheck_list);
    }
  }
  
  if (pair) {
    priv_conn_check_initiate (agent, pair);
    keep_timer_going = TRUE;
  }

  {
    GTimeVal now;
    int frozen = 0, inprogress = 0, waiting = 0;

    g_get_current_time (&now);

    for (i = agent->conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;

      if (p->state == NICE_CHECK_IN_PROGRESS) {
	/* note: macro from sys/time.h but compatible with GTimeVal */
	if (p->stun_ctx == NULL) {
	  g_debug ("STUN connectivity check was cancelled, marking as done.");
	  p->state = NICE_CHECK_FAILED;
	}
	else if (timercmp(&p->next_tick, &now, <=)) {
	  int res = stun_bind_elapse (p->stun_ctx);
	  if (res == EAGAIN) {
	    /* case: not ready complete, so schedule next timeout */
	    unsigned int timeout = stun_bind_timeout (p->stun_ctx);
	  
	    /* note: convert from milli to microseconds for g_time_val_add() */
	    g_get_current_time (&p->next_tick);
	    g_time_val_add (&p->next_tick, timeout * 10);

	    keep_timer_going = TRUE;
	  }
	  else {
	    /* case: error, abort processing */
	    g_debug ("Retransmissions failed, giving up on connectivity check %p", p);
	    p->state = NICE_CHECK_FAILED;
	  }
	}
      }

      if (p->state == NICE_CHECK_FROZEN)
	++frozen;
      if (p->state == NICE_CHECK_IN_PROGRESS)
	++inprogress;
      else if (p->state == NICE_CHECK_WAITING)
	++waiting;
    }

#ifdef DEBUG
    {
      static int tick_counter = 0;
      if (++tick_counter % 20 == 0 || keep_timer_going != TRUE)
	g_debug ("timer: %d frozen, %d in-progress, %d waiting.", frozen, inprogress, waiting);
    }
#endif

    /* note: keep the timer going as long as there is work to be done */
    if (frozen || inprogress || waiting)
      keep_timer_going = TRUE;
  }

  if (keep_timer_going != TRUE) {
    g_debug ("%s: stopping conncheck timer", G_STRFUNC);
    for (i = agent->streams; i; i = i->next) {
      Stream *stream = i->data;
      priv_update_check_list_state (agent, stream);
    }
    
    conn_check_free (agent);
  }

  return keep_timer_going;
}

/**
 * Initiates the next pending connectivity check.
 */
void conn_check_schedule_next (NiceAgent *agent)
{
  gboolean c = priv_conn_check_unfreeze_next (agent->conncheck_list);

  if (c == TRUE) {
    /* step: call once imediately */
    gboolean res = priv_conn_check_tick ((gpointer) agent);

    /* step: schedule timer if not running yet */
    /* XXX: make timeout Ta configurable */
    if (agent->conncheck_timer_id == 0 && res != FALSE) 
      agent->conncheck_timer_id = 
	g_timeout_add (NICE_AGENT_TIMER_TA_DEFAULT, priv_conn_check_tick, agent);
  }
}

/**
 * Forms new candidate pairs by matching the new remote candidate
 * 'remote_cand' with all existing local candidates of 'component'.
 * Implements the logic described in sect 5.7.1 of ICE -15 spec.
 *
 * @param agent context
 * @param component pointer to the component
 * @param remote remote candidate to match with
 *
 * @return non-zero on error
 */
int conn_check_add_for_candidate (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *remote)
{
  GSList *i;
  int res = 0; 

  for (i = component->local_candidates; i ; i = i->next) {

    NiceCandidate *local = i->data;
    CandidateCheckPair *pair = g_slice_new0 (CandidateCheckPair);
    if (pair) {

      /* XXX: as per -15 5.7.3, filter pairs where local candidate is
	 srvrflx and base matches a local candidate for which there
	 already is a check pair 
      */

      pair->agent = agent;
      pair->stream_id = stream_id;
      pair->component_id = component->id;;
      pair->local = local; /* XXX: hmm, do we need reference counting,
			      or we just make sure all connchecks are
			      destroyed before any components of a stream...? */
      pair->remote = remote;
      pair->foundation = g_strdup_printf ("%s%s", local->foundation, remote->foundation);
      if (!pair->foundation) {
	g_slice_free (CandidateCheckPair, pair);
	res = -1;
	break;
      }

      pair->priority = nice_candidate_pair_priority (local->priority, remote->priority);
      pair->state = NICE_CHECK_FROZEN;

      if (!agent->conncheck_list)
	agent->conncheck_state = NICE_CHECKLIST_RUNNING;
      
      agent->conncheck_list = g_slist_append (agent->conncheck_list, pair);

      if (!agent->conncheck_list)
	agent->conncheck_state = NICE_CHECKLIST_FAILED;

      g_debug ("added a new conncheck item with foundation of '%s'.", pair->foundation);
    }
    else {
      res = -1;
      break;
    }
  }

  return res;
}

/**
 * Frees the CandidateCheckPair structure pointer to 
 * by 'user data'. Compatible with g_slist_foreach().
 */
void conn_check_free_item (gpointer data, gpointer user_data)
{
  CandidateCheckPair *pair = data;
  g_assert (user_data == NULL);
  if (pair->foundation)
    g_free (pair->foundation),
      pair->foundation = NULL;
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
    if (agent->conncheck_timer_id) {
      g_source_remove (agent->conncheck_timer_id),
	agent->conncheck_timer_id = 0;
    }
    agent->conncheck_state = NICE_CHECKLIST_NOT_STARTED;
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

  g_debug ("pruning stream %u conn checks.", stream_id);

  for (i = agent->conncheck_list; i ; ) {
    pair = i->data;

    if (pair->stream_id == stream_id) {
      GSList *next = i->next;
      g_debug ("conncheck, pruning item %p.", i);
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

  if (!agent->conncheck_list)
    agent->conncheck_state = NICE_CHECKLIST_NOT_STARTED;

  /* return FALSE if there was a memory allocation failure */
  if (agent->conncheck_list == NULL && i != NULL)
    return FALSE;

  return TRUE;
}


/**
 * Returns a username string for use in an outbound connectivity
 * check. The caller is responsible for freeing the returned
 * string.
 */
static gchar *priv_create_check_username (NiceAgent *agent, CandidateCheckPair *pair)
{
  Stream *stream;

  if (pair &&
      pair->remote && pair->remote->username &&
      pair->local && pair->local->username)
    return g_strconcat (pair->remote->username, ":", pair->local->username, NULL);

  stream = agent_find_stream (agent, pair->stream_id);
  if (stream)
    return g_strconcat (stream->remote_ufrag, ":", stream->local_ufrag, NULL);

  return NULL;
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
  /* XXX: memory allocs: */
  gchar *username = priv_create_check_username (agent, pair);
  const gchar *password = priv_create_check_password (agent, pair);
  bool controlling = agent->controlling_mode;
 /* XXX: add API to support different nomination modes: */
  bool cand_use = controlling;

  uint64_t tie;
  struct sockaddr sockaddr;
  unsigned int timeout;

  memset (&sockaddr, 0, sizeof (sockaddr)); 
  nice_rng_generate_bytes (agent->rng, 4, (gchar*)&tie);

  nice_address_copy_to_sockaddr (&pair->remote->addr, &sockaddr);

  g_debug ("sending STUN conncheck, port:%u, socket:%u, tie:%llu, username:'%s', password:'%s', priority:%u.", 
	   ntohs(((struct sockaddr_in*)(&sockaddr))->sin_port), 
	   pair->local->sockptr->fileno,
	   (unsigned long long)tie,
	   username, password, priority);

  if (cand_use) 
    pair->nominated = TRUE;

  stun_conncheck_start (&pair->stun_ctx, pair->local->sockptr->fileno,
			&sockaddr, sizeof (sockaddr),
			username, password,
			cand_use, controlling, priority,
			tie);

  timeout = stun_bind_timeout (pair->stun_ctx);
  /* note: convert from milli to microseconds for g_time_val_add() */
  g_get_current_time (&pair->next_tick);
  g_time_val_add (&pair->next_tick, timeout * 10);

  g_debug ("set timeout for conncheck %p to %u.", pair, timeout);

  if (username)
    g_free (username);
  
  return 0;
}

/**
 * Updates the check list state.
 *
 * Implements parts of the algorithm described in ICE ID-15 8.2
 * that apply to the whole check list.
 */
static void priv_update_check_list_state (NiceAgent *agent, Stream *stream)
{
  GSList *i;
  guint c, completed = 0;

  /* note: iterate the conncheck list for each component separately */
  for (c = 0; c < stream->n_components; c++) {
    guint not_failed = 0;
    for (i = agent->conncheck_list; i; i = i->next) {
      CandidateCheckPair *p = i->data;
      
      if (p->stream_id == stream->id &&
	  p->component_id == (c + 1)) {
	if (p->state != NICE_CHECK_FAILED)
	  ++not_failed;

	if (p->state == NICE_CHECK_SUCCEEDED &&
	    p->nominated == TRUE)
	  break;
      }
    }

    /* note: all checks have failed */
    if (!not_failed)
      agent_signal_component_state_change (agent, 
					   stream->id,
					   (c + 1), /* component-id */
					   NICE_COMPONENT_STATE_FAILED);

    /* note: no pair was ready&nominated */
    if (i == NULL) 
      ++completed;
  }

  if (completed == stream->n_components) {
    /* note: all components completed */
    /* XXX: not really true as there can be checks for multiple
     *      streams in the conncheck list... :o */
    agent->conncheck_state = NICE_CHECKLIST_COMPLETED;
    /* XXX: what to signal, is all processing now really done? */
    g_debug ("changing conncheck state to COMPLETED)");
  }
}

/**
 * Updated the check list state for a stream component.
 *
 * Implements the algorithm described in ICE ID-15 8.2 as
 * it applies to checks of a certain component. 
 */
static void priv_update_check_list_state_for_component (NiceAgent *agent, Stream *stream, Component *component)
{
  GSList *i;
  unsigned int succeeded = 0, nominated = 0;

  g_assert (component);

  /* step: search for at least one nominated pair */
  for (i = agent->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component->id) {
      if (p->state == NICE_CHECK_SUCCEEDED) {
	++succeeded;
	if (p->nominated == TRUE) {
	  ++nominated;
	  agent_signal_component_state_change (agent,
					       p->stream_id,
					       p->component_id,
					       NICE_COMPONENT_STATE_READY);
	}
      }
    }
  }
  
  g_debug ("conn.check list status: %u nominated, %u succeeded, c-id %u.", nominated, succeeded, component->id);

  if (nominated) {
    /* step: cancel all FROZEN and WAITING pairs for the component */
    for (i = agent->conncheck_list; i; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (p->state == NICE_CHECK_FROZEN ||
	  p->state == NICE_CHECK_WAITING)
	p->state = NICE_CHECK_CANCELLED;

      /* note: a SHOULD level req. in ICE ID-15: */
      if (p->state == NICE_CHECK_IN_PROGRESS) {
	if (p->stun_ctx)
	  stun_bind_cancel (p->stun_ctx),
	    p->stun_ctx = NULL;
	p->state = NICE_CHECK_CANCELLED;
      }
    }
  }

  priv_update_check_list_state (agent, stream);
}

/**
 * Changes the selected pair for the component if 'pair' is nominated
 * and has higher priority than the currently selected pair. See
 * ICE sect 11.1.1 (ID-15).
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
 * The remote party has signalled that the candidate pair
 * described by 'component' and 'remotecand' is nominated
 * for use.
 */
static void priv_mark_pair_nominated (NiceAgent *agent, Component *component, NiceCandidate *remotecand)
{
  GSList *i;

  g_assert (component);

  /* step: search for at least one nominated pair */
  for (i = agent->conncheck_list; i; i = i->next) {
    CandidateCheckPair *pair = i->data;
    /* XXX: hmm, how figure out to which local candidate the 
     *      check was sent to? let's mark all matching pairs
     *      as nominated instead */
    if (pair->remote == remotecand) {
      g_debug ("marking pair %p (%s) as nominated", pair, pair->foundation);
      pair->nominated = TRUE;
      if (pair->state == NICE_CHECK_SUCCEEDED)
	priv_update_selected_pair (agent, component, pair);
    }
  }

}

gboolean conn_check_handle_inbound_stun (NiceAgent *agent, Stream *stream, Component *component, const NiceAddress *from, gchar *buf, guint len)
{
  struct sockaddr sockaddr;
  uint8_t rbuf[MAX_STUN_DATAGRAM_PAYLOAD];
  ssize_t res;
  size_t rbuf_len = sizeof (rbuf);
  bool control = agent->controlling_mode;
  uint64_t tie = -1; /* XXX: fix properly */

  nice_address_copy_to_sockaddr (from, &sockaddr);

  /* note: contents of 'buf' already validated, so it is 
   *       a valid and full received STUN message */

  /* note: ICE ID-15, 7.2 */

  res = stun_conncheck_reply (rbuf, &rbuf_len, (const uint8_t*)buf, &sockaddr, sizeof (sockaddr), 
			      stream->local_password, &control, tie);
  if (res == 0) {
    /* case 1: valid incoming request, send a reply */
    GSList *i;
    NiceUDPSocket *local_sock = NULL;
    bool use_candidate = 
      stun_conncheck_use_candidate ((const uint8_t*)buf);

    if (stream->initial_binding_request_received != TRUE)
      agent_signal_initial_binding_request_received (agent, stream);

    if (control != agent->controlling_mode) {
      g_debug ("Conflict in controller selection, switching to mode %d.", control);
      agent->controlling_mode = control;
    }

    /* XXX/hack: until the socket refactoring is done, use the below hack */    
    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (cand->sockptr->fileno > 0)
	local_sock = cand->sockptr;
    }

    for (i = component->remote_candidates; local_sock && i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (nice_address_equal (from, &cand->addr)) {
	g_debug ("Sending a conncheck reply (fileno=%u, addr=%p, res=%u, buf=%p).",
		 local_sock->fileno, &cand->addr, rbuf_len, rbuf);

	nice_udp_socket_send (local_sock, &cand->addr, rbuf_len, (const gchar*)rbuf);

	if (use_candidate)
	  priv_mark_pair_nominated (agent, component, cand);

	/* XXX: perform a triggered check */

	break;
      }
    }

    /* XXX: add support for discovering peer-reflexive candidates */
    if (i == NULL) 
      g_debug ("No matching remote candidate for incoming STUN conncheck.");

  }
  else if (res == EINVAL) {
    /* case 2: not a valid, new request -- continue processing */
    GSList *i;
    int res;
    socklen_t socklen = sizeof (sockaddr);
    gboolean trans_found = FALSE;

    g_debug ("Not a STUN connectivity check request -- might be a reply...");
    
    /* note: ICE ID-15, 7.1.2 */

    /* step: let's try to match the response to an existing check context */
    for (i = agent->conncheck_list; i && trans_found != TRUE; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (p->stun_ctx) {
	res = stun_bind_process (p->stun_ctx, buf, len, &sockaddr, &socklen); 
	g_debug ("stun_bind_process/conncheck for %p res %d.", p, res);
	if (res == 0) {
	  /* case: succesful connectivity check */
	  g_debug ("conncheck %p SUCCEED.", p);
	  p->state = NICE_CHECK_SUCCEEDED;
	  p->stun_ctx = NULL;
	  /* note: CONNECTED but not yet READY, see docs */
	  agent_signal_component_state_change (agent, 
					       stream->id,
					       component->id,
					       NICE_COMPONENT_STATE_CONNECTED);
	  priv_update_check_list_state_for_component (agent, stream, component);
	  if (p->nominated == TRUE) {
	    priv_update_selected_pair (agent, component, p);
	  }
	  trans_found = TRUE;
	}
	else if (res != EAGAIN) {
	  /* case: STUN error, the check STUN context was freed */
	  g_debug ("conncheck %p FAILED.", p);
	  p->stun_ctx = NULL;
	  trans_found = TRUE;
	}
	else
	  /* case: invalid/incomplete message */
	  g_assert (res == EAGAIN);
      }
    }

    /* step: let's try to match the response to an existing discovery */
    for (i = agent->discovery_list; i  && trans_found != TRUE; i = i->next) {
      CandidateDiscovery *d = i->data;
      res = stun_bind_process (d->stun_ctx, buf, len, &sockaddr, &socklen); 
      g_debug ("stun_bind_process/disc for %p res %d.", d, res);
      if (res == 0) {
	/* case: succesful binding discovery, create a new local candidate */
	NiceAddress niceaddr;
	struct sockaddr_in *mapped = (struct sockaddr_in *)&sockaddr;
	niceaddr.type = NICE_ADDRESS_TYPE_IPV4;
	niceaddr.addr_ipv4 = ntohl(mapped->sin_addr.s_addr);
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
	trans_found = TRUE;
      }
    }
  }
  else {
    g_debug ("Invalid STUN connectivity check request. Ignoring... %s", strerror(errno));
  }

  return TRUE;
}

/* -----------------------------------------------------------------
 * Code using the old STUN API 
 * ----------------------------------------------------------------- */

static void
_handle_stun_binding_request (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceCandidate *local,
  NiceAddress from,
  StunMessage *msg)
{
  GSList *i;
  StunAttribute *attr;
  gchar *username = NULL;
  NiceCandidate *remote = NULL;

  /* msg should have either:
   *
   *   Jingle P2P:
   *     username = local candidate username + remote candidate username
   *   ICE:
   *     username = local candidate username + ":" + remote candidate username
   *     password = local candidate pwd
   *     priority = priority to use if a new candidate is generated
   *
   * Note that:
   *
   *  - "local"/"remote" are from the perspective of the receiving side
   *  - the remote candidate username is not necessarily unique; Jingle seems
   *    to always generate a unique username/password for each candidate, but
   *    ICE makes no guarantees
   *
   * There are three cases we need to deal with:
   *
   *  - valid username with a known address
   *    --> send response
   *  - valid username with an unknown address
   *    --> send response
   *    --> later: create new remote candidate
   *  - invalid username
   *    --> send error
   */

  attr = stun_message_find_attribute (msg, STUN_ATTRIBUTE_USERNAME);

  if (attr == NULL)
    /* no username attribute found */
    goto ERROR;

  username = attr->username;

  /* validate username */
  /* XXX-old_stun_code: Should first try and find a remote candidate with a matching
   * transport address, and fall back to matching on username only after that.
   * That way, we know to always generate a new remote candidate if the
   * transport address didn't match.
   */

  for (i = component->remote_candidates; i; i = i->next)
    {
      guint len;

      remote = i->data;

#if 0
      g_debug ("uname check: %s :: %s -- %s", username, local->username,
          remote->username);
#endif

      if (!g_str_has_prefix (username, local->username))
        continue;

      len = strlen (local->username);

      if (0 != strcmp (username + len, remote->username))
        continue;

#if 0
      /* usernames match; check address */

      if (rtmp->addr.addr_ipv4 == ntohl (from.sin_addr.s_addr) &&
          rtmp->port == ntohs (from.sin_port))
        {
          /* this is a candidate we know about, just send a reply */
          /* is candidate pair active now? */
          remote = rtmp;
        }
#endif

      /* send response */
      goto RESPOND;
    }

  /* username is not valid */
  goto ERROR;

RESPOND:

#ifdef DEBUG
    {
      gchar ip[NICE_ADDRESS_STRING_LEN];

      nice_address_to_string (&remote->addr, ip);
      g_debug ("s%d:%d: got valid connectivity check for candidate %d (%s:%d)",
          stream->id, component->id, remote->id, ip, remote->addr.port);
    }
#endif

  /* update candidate/peer affinity */
  /* Note that @from might be different to @remote->addr; for ICE, this
   * (always?) creates a new peer-reflexive remote candidate (§7.2).
   */
  /* XXX-old_stun_code: test case where @from != @remote->addr. */

  component->active_candidate = local;
  component->peer_addr = from;

  /* send STUN response */

    {
      StunMessage *response;
      guint len;
      gchar *packed;

      response = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE,
          msg->transaction_id, 2);
      response->attributes[0] = stun_attribute_mapped_address_new (
          from.addr_ipv4, from.port);
      response->attributes[1] = stun_attribute_username_new (username);
      len = stun_message_pack (response, &packed);
      nice_udp_socket_send (local->sockptr, &from, len, packed);

      g_free (packed);
      stun_message_free (response);
    }

  /* send reciprocal ("triggered") connectivity check */
  /* XXX-old_stun_code: possibly we shouldn't do this if we're being an ICE Lite agent */

    {
      StunMessage *extra;
      gchar *username;
      guint len;
      gchar *packed;

      extra = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          NULL, 1);

      username = g_strconcat (remote->username, local->username, NULL);
      extra->attributes[0] = stun_attribute_username_new (username);
      g_free (username);

      nice_rng_generate_bytes (agent->rng, 16, extra->transaction_id);

      len = stun_message_pack (extra, &packed);
      nice_udp_socket_send (local->sockptr, &from, len, packed);
      g_free (packed);

      stun_message_free (extra);
    }

  /* emit component-state-changed(connected) */
  /* XXX-old_stun_code: probably better do this when we get the binding response */
    agent_signal_component_state_change (agent, 
					 stream->id,
					 component->id,
					 NICE_COMPONENT_STATE_CONNECTED);

  return;

ERROR:

#ifdef DEBUG
    {
      gchar ip[NICE_ADDRESS_STRING_LEN];

      nice_address_to_string (&remote->addr, ip);
      g_debug (
          "s%d:%d: got invalid connectivity check for candidate %d (%s:%d)",
          stream->id, component->id, remote->id, ip, remote->addr.port);
    }
#endif

  /* XXX-old_stun_code: add ERROR-CODE parameter */

    {
      StunMessage *response;
      guint len;
      gchar *packed;

      response = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          msg->transaction_id, 0);
      len = stun_message_pack (response, &packed);
      nice_udp_socket_send (local->sockptr, &from, len, packed);

      g_free (packed);
      stun_message_free (response);
    }

  /* XXX-old_stun_code: we could be clever and keep around STUN packets that we couldn't
   * validate, then re-examine them when we get new remote candidates -- would
   * this fix some timing problems (i.e. TCP being slower than UDP)
   */
  /* XXX-old_stun_code: if the peer is the controlling agent, it may include a USE-CANDIDATE
   * attribute in the binding request
   */
}

void conn_check_handle_inbound_stun_old (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceCandidate *local,
  NiceAddress from,
  StunMessage *msg)
{
  switch (msg->type)
    {
    case STUN_MESSAGE_BINDING_REQUEST:
      _handle_stun_binding_request (agent, stream, component, local, from,
          msg);
      break;
    case STUN_MESSAGE_BINDING_RESPONSE:
      /* XXX-old_stun_code: check it matches a request we sent */
      break;
    default:
      /* a message type we don't know how to handle */
      /* XXX-old_stun_code: send error response */
      break;
    }
}


