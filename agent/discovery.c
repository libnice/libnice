/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
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

#include <string.h>
#include <errno.h>

#ifndef _BSD_SOURCE
#error "timercmp() macros needed"
#endif
#include <sys/time.h> /* timercmp() macro, BSD */

#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include "agent.h"
#include "agent-priv.h"
#include "agent-signals-marshal.h"
#include "component.h"
#include "discovery.h"

/**
 * Frees the CandidateDiscovery structure pointed to 
 * by 'user data'. Compatible with g_slist_foreach().
 */
void discovery_free_item (gpointer data, gpointer user_data)
{
  CandidateDiscovery *cand = data;
  g_assert (user_data == NULL);
  cand->server_addr = NULL;
  g_slice_free (CandidateDiscovery, cand);
}

/**
 * Frees all discovery related resources for the agent.
 */
void discovery_free (NiceAgent *agent)
{
  if (agent->discovery_list) {
    g_slist_foreach (agent->discovery_list, discovery_free_item, NULL);
    g_slist_free (agent->discovery_list),
      agent->discovery_list = NULL;

    if (agent->discovery_timer_id)
      g_source_remove (agent->discovery_timer_id),
	agent->discovery_timer_id = 0;

    agent->discovery_unsched_items = 0;
  }
}

/**
 * Prunes the list of discovery processes for items related
 * to stream 'stream_id'. 
 *
 * @return TRUE on success, FALSE on a fatal error
 */
gboolean discovery_prune_stream (NiceAgent *agent, guint stream_id)
{
  CandidateDiscovery *cand;
  GSList *i;

  g_debug ("pruning stream %u discovery items.", stream_id);

  for (i = agent->discovery_list; i ; ) {
    cand = i->data;

    if (cand->stream->id == stream_id) {
      GSList *next = i->next;
      g_debug ("discovery, pruning item %p.", i);
      agent->discovery_list = 
	g_slist_remove (agent->discovery_list, cand);
      discovery_free_item (cand, NULL);
      i = next;
      if (!agent->discovery_list)
	break;
    }
    else
      i = i->next;
  }

  /* return FALSE if there was a memory allocation failure */
  if (agent->conncheck_list == NULL && i != NULL)
    return FALSE;

  return TRUE;
}

/**
 * Creates a local host candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate *discovery_add_local_host_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  NiceUDPSocket *udp_socket = NULL;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  if (candidate) {
    NiceUDPSocket *udp_socket = g_slice_new0 (NiceUDPSocket);
    if (udp_socket) {
      candidate->foundation = g_strdup_printf ("%u", agent->next_candidate_id++);
      candidate->stream_id = stream_id;
      candidate->component_id = component_id;
      candidate->addr = *address;
      candidate->base_addr = *address;
      candidate->priority = nice_candidate_ice_priority (candidate);

      /* note: username and password set to NULL as stream
	 ufrag/password are used */
      
      if (nice_udp_socket_factory_make (agent->socket_factory,
					udp_socket, address)) {
	
	component->local_candidates = g_slist_append (component->local_candidates,
						    candidate);
	if (component->local_candidates) {
	  component->sockets = g_slist_append (component->sockets, udp_socket);
	  if (component->sockets) {
	    /* success: store a pointer to the sockaddr */
	    candidate->sockptr = udp_socket;
	    candidate->addr = udp_socket->addr;
	    candidate->base_addr = udp_socket->addr;
	    agent_signal_new_candidate (agent, candidate);
	  }
	  else { /* error: list memory allocation */
	    candidate = NULL; 
	    /* note: candidate already owner by component */
	  }
	}
	else { /* error: memory alloc / list */
	  nice_candidate_free (candidate), candidate = NULL;
	}
      }
      else { /* error: socket factory make */
	nice_candidate_free (candidate), candidate = NULL;
      }
    }
    else /* error: udp socket memory allocation */
      nice_candidate_free (candidate), candidate = NULL;
  }

  if (!candidate) {
    /* clean up after errors */
    if (udp_socket)
      g_slice_free (NiceUDPSocket, udp_socket);
  }
  
  return candidate;
}

/**
 * Creates a server reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */

NiceCandidate* 
discovery_add_server_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceUDPSocket *base_socket)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
  if (candidate) {
    candidate->foundation = g_strdup_printf ("%u", agent->next_candidate_id++);
    candidate->stream_id = stream_id;
    candidate->component_id = component_id;
    candidate->addr = *address;
    candidate->base_addr = *address;

    /* step: link to the base candidate+socket */
    candidate->sockptr = base_socket;
    candidate->base_addr = base_socket->addr;

    candidate->priority = 
      0x1000000 * 125 + 0x100 * 0 + 256 - component_id; /* sect:4.1.2.1(-14) */
    
    component->local_candidates = g_slist_append (component->local_candidates,
						  candidate);
    if (component->local_candidates) {
      /* note: username and password left to NULL as stream-evel
       *       credentials are used by default */
      
      g_assert (candidate->username == NULL);
      g_assert (candidate->password == NULL);
    }
    else /* error: memory allocation - list */
      nice_candidate_free (candidate), candidate = NULL;
  }

  return candidate;
  }

/** 
 * Timer callback that handles scheduling new candidate discovery
 * processes (paced by the Ta timer), and handles running of the 
 * existing discovery processes.
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_discovery_tick (gpointer pointer)
{
  CandidateDiscovery *cand;
  NiceAgent *agent = pointer;
  GSList *i;
  int not_done = 0; /* note: track whether to continue timer */

#ifdef DEBUG
  {
    static int tick_counter = 0;
    if (++tick_counter % 20 == 0)
      g_debug ("discovery tick #%d with list %p (1)", tick_counter, agent->discovery_list);
  }
#endif

  for (i = agent->discovery_list; i ; i = i->next) {
    cand = i->data;

    if (cand->pending != TRUE) {
      cand->pending = TRUE;

      if (agent->discovery_unsched_items)
	--agent->discovery_unsched_items;
      
      g_debug ("discovery - scheduling cand type %u addr %s and socket %d.\n", cand->type, cand->server_addr, cand->socket);
      
      if (cand->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
	  cand->server_addr) {
	
	struct sockaddr_in stun_server;
	int res;

	memset (&stun_server, 0, sizeof(stun_server));
	
	stun_server.sin_addr.s_addr = inet_addr(cand->server_addr);
	stun_server.sin_port = htons(IPPORT_STUN);

	res = stun_bind_start (&cand->stun_ctx, cand->socket, 
			 (struct sockaddr*)&stun_server, sizeof(stun_server));
	
	if (res == 0) {
	  /* case: success, start waiting for the result */
	  g_get_current_time (&cand->next_tick);

	  agent_signal_component_state_change (agent, 
					       cand->stream->id,
					       cand->component->id,
					       NICE_COMPONENT_STATE_GATHERING);

	}
	else {
	  /* case: error in starting discovery, start the next discovery */
	  cand->done = TRUE;
	  cand->stun_ctx = NULL;
	  continue; 
	}
      }
      else 
	/* allocate relayed candidates */
	g_assert_not_reached ();
      
      ++not_done; /* note: new discovery scheduled */
    }
    
    if (cand->done != TRUE) {
      GTimeVal now;

      g_get_current_time (&now);

      if (cand->stun_ctx == NULL) {
	g_debug ("STUN discovery was cancelled, marking discovery done.");
	cand->done = TRUE;
      }
      /* note: macro from sys/time.h but compatible with GTimeVal */
      else if (timercmp(&cand->next_tick, &now, <=)) {
	int res = stun_bind_elapse (cand->stun_ctx);
	if (res == EAGAIN) {
	  /* case: not ready complete, so schedule next timeout */
	  unsigned int timeout = stun_bind_timeout (cand->stun_ctx);
	  
	  /* note: convert from milli to microseconds for g_time_val_add() */
	  g_get_current_time (&cand->next_tick);
	  g_time_val_add (&cand->next_tick, timeout * 10);
	  
	  /* note: macro from sys/time.h but compatible with GTimeVal */
	  if (timercmp(&cand->next_tick, &agent->next_check_tv, <)) {
	    agent->next_check_tv = cand->next_tick;
	  }
	  
	  ++not_done; /* note: retry later */
	}
	else {
	  /* case: error, abort processing */
	  cand->done = TRUE;
	  cand->stun_ctx = NULL;
	  g_debug ("Error with stun_bind_elapse(), aborting discovery item.");
	}
       
      }
      else
	++not_done; /* note: discovery not expired yet */
    }
  }

  if (not_done == 0) {
    g_debug ("Candidate gathering FINISHED, stopping discovery timer.");

    agent_signal_gathering_done (agent);
    discovery_free (agent);

    /* note: no pending timers, return FALSE to stop timer */
    return FALSE;
  }

  return TRUE;
}

/**
 * Initiates the active candidate discovery process.
 *
 * @pre agent->discovery_list != NULL  // unsched discovery items available
 */
void discovery_schedule (NiceAgent *agent)
{
  g_assert (agent->discovery_list != NULL);

  g_debug ("Scheduling discovery...");

  if (agent->discovery_unsched_items > 0) {
    
    /* XXX: make timeout Ta configurable */
    guint next = NICE_AGENT_TIMER_TA_DEFAULT; 

    /* XXX: send a component state-change, but, but, how do we
     * actually do this? back to the drawing board... */

    /* step 1: run first iteration immediately */
    priv_discovery_tick (agent);

    g_debug ("Scheduling a discovery timeout of %u msec.", next);

    /* step 2: scheduling timer */
    agent->discovery_timer_id = 
      g_timeout_add (next, priv_discovery_tick, agent);
  }
}
