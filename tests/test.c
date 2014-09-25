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
#endif

#include <string.h>

#include "agent.h"
#include "agent-priv.h"

/* Waits about 10 seconds for @var to be NULL/FALSE */
#define WAIT_UNTIL_UNSET(var, context)			\
  if (var)						\
    {							\
      int _i;						\
							\
      for (_i = 0; _i < 13 && (var); _i++)		\
	{						\
	  g_usleep (1000 * (1 << _i));			\
	  g_main_context_iteration (context, FALSE);	\
	}						\
							\
      g_assert (!(var));				\
    }

gint
main (void)
{
  NiceAgent *agent;
  NiceAddress addr_local, addr_remote;
  NiceCandidate *candidate;
  GSList *candidates, *i;
  guint stream_id;

#ifdef G_OS_WIN32
  WSADATA w;

  WSAStartup(0x0202, &w);
#endif

  nice_address_init (&addr_local);
  nice_address_init (&addr_remote);
  g_type_init ();

  g_thread_init(NULL);

  g_assert (nice_address_set_from_string (&addr_local, "127.0.0.1"));
  g_assert (nice_address_set_from_string (&addr_remote, "127.0.0.1"));
  nice_address_set_port (&addr_remote, 2345);

  agent = nice_agent_new ( NULL, NICE_COMPATIBILITY_RFC5245);
  g_object_set (G_OBJECT (agent), "ice-tcp", FALSE,  NULL);

  g_assert (agent->local_addresses == NULL);

  /* add one local address */
  nice_agent_add_local_address (agent, &addr_local);

  g_assert (agent->local_addresses != NULL);
  g_assert (g_slist_length (agent->local_addresses) == 1);
  g_assert (nice_address_equal (agent->local_addresses->data, &addr_local));

  /* add a stream */
  stream_id = nice_agent_add_stream (agent, 1);
  nice_agent_gather_candidates (agent, stream_id);

  /* adding a stream should cause host candidates to be generated */
  candidates = nice_agent_get_local_candidates (agent, stream_id, 1);
  g_assert (g_slist_length (candidates) == 1);
  candidate = candidates->data;
  /* socket manager uses random port number */
  nice_address_set_port (&addr_local, 1);
  nice_address_set_port (&(candidate->addr), 1);
  g_assert (nice_address_equal (&(candidate->addr), &addr_local));
  g_assert (strncmp (candidate->foundation, "1", 1) == 0);
  for (i = candidates; i; i = i->next)
    nice_candidate_free ((NiceCandidate *) i->data);
  g_slist_free (candidates);

  /* clean up */
  nice_agent_remove_stream (agent, stream_id);

  g_object_add_weak_pointer (G_OBJECT (agent), (gpointer *) &agent);
  g_object_unref (agent);
  WAIT_UNTIL_UNSET (agent, NULL);

#ifdef G_OS_WIN32
  WSACleanup();
#endif
  return 0;
}

