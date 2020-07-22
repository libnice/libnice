/*
 * This file is part of the Nice GLib ICE library.
 *
 * Unit test for ICE full-mode related features.
 *
 * (C)2020 Collabora Ltd
 *  @author: Olivier Crete <olivier.crete@collabora.com>
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
 *
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

#include "agent.h"

#include <stdlib.h>
#include <string.h>

int main (int argc, char **argv)
{
  NiceAgent *agent;
  guint stream1;

#ifdef G_OS_WIN32
  WSADATA w;

  WSAStartup(0x0202, &w);
#endif

  agent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);

  stream1 = nice_agent_add_stream (agent, 2);

  nice_agent_set_port_range (agent, stream1, 1, 8888, 8888);
  nice_agent_set_port_range (agent, stream1, 2, 8888, 8888);

  /* First test with ICE-TCP enabled, this should fail on creating the port */
  g_assert (nice_agent_gather_candidates (agent, stream1) == FALSE);

  /* First test with ICE-TCP disabled, this should fail on our explicit test */
  g_object_set (agent, "ice-tcp", FALSE, NULL);
  g_assert (nice_agent_gather_candidates (agent, stream1) == FALSE);

  nice_agent_set_port_range (agent, stream1, 2, 9999, 9999);
  g_assert (nice_agent_gather_candidates (agent, stream1));

  g_object_unref (agent);

#ifdef G_OS_WIN32
  WSACleanup();
#endif
  return 0;
}
