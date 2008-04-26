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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include "udp-fake.h"
#include "agent.h"

int
main (void)
{
  NiceAgent *agent;
  NiceAddress addr;
  NiceUDPSocketFactory factory;
  guint stream_id;

  nice_address_init (&addr);
  g_type_init ();
  g_thread_init (NULL);

  nice_udp_fake_socket_factory_init (&factory);

  /* set up agent */
  agent = nice_agent_new (&factory, NULL, NICE_COMPATIBILITY_ID19);
  g_assert (nice_address_set_from_string (&addr, "192.168.0.1"));
  nice_agent_add_local_address (agent, &addr);
  stream_id = nice_agent_add_stream (agent, 1);
  nice_agent_gather_candidates (agent, stream_id);

  /* recieve an RTP packet */

    {
      NiceCandidate *candidate;
      NiceUDPSocket *sock;
      guint len;
      gchar buf[1024];
      GSList *candidates;

      candidates = nice_agent_get_local_candidates (agent, stream_id, 1);
      candidate = candidates->data;
      g_slist_free (candidates);
      sock = candidate->sockptr;
      nice_udp_fake_socket_push_recv (sock, &addr, 7, "\x80lalala");
      len = nice_agent_recv (agent, stream_id,
          candidate->component_id, 1024, buf);
      g_assert (len == 7);
      g_assert (0 == strncmp (buf, "\x80lalala", 7));
    }

  /* clean up */
  g_object_unref (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

