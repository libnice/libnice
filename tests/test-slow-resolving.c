/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
 * (C) 2025 Johan Sternerup <johast@axis.com>
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
 *   Johan Sternerup, Axis Communications AB
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
#include "candidate.h"
#include "glib.h"
#include "glibconfig.h"
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "agent.h"
#include "agent-priv.h"

#include <netdb.h>

#define MAX_CLOSING_TIME_MICRO_SECONDS (100 * 1000)     /* Should be fast, 100ms is more than enough */
#define MAX_WAIT_FOR_RESOLVE_MICRO_SECONDS (100 * 1000) /* Should be enough for a context switch to worker context */

static GMainLoop *agent_mainloop = NULL;
static GMainContext *agent_mainctxt = NULL;

static gpointer
agent_thread_cb (gpointer data)
{
  g_main_context_push_thread_default (agent_mainctxt);
  g_main_loop_run (agent_mainloop);
  g_main_context_pop_thread_default (agent_mainctxt);

  return NULL;
}

/* see slow-resolver.c */
static guint
get_num_resolvers_in_progress (void)
{
  return getaddrinfo ("query.bogus.nonexisting", NULL, NULL, NULL);
}

/* see slow-resolver.c */
static void
finish_resolver_operations (void)
{
  g_assert_cmpint (0, ==, getaddrinfo ("cancel.bogus.nonexisting", NULL, NULL,
          NULL));
}

/* see slow-resolver.c */
static void
block_resolver_operations (void)
{
  g_assert_cmpint (0, ==, getaddrinfo ("block.bogus.nonexisting", NULL, NULL,
          NULL));
}

static guint
get_num_open_file_descriptors (void)
{
  GDir *dir;
  const gchar *fname;
  guint count = 0;

  dir = g_dir_open ("/proc/self/fd", 0, NULL);
  g_assert_nonnull (dir);

  fname = g_dir_read_name (dir);
  while (fname != NULL) {
    count++;
    fname = g_dir_read_name (dir);
  }
  g_dir_close (dir);

  g_print ("NUM FD %u\n", count);
  return count;
}

static void
agent_close_cb (GObject * source_object, GAsyncResult * res, gpointer data)
{
  guint *agent_closed = data;

  *agent_closed = 1;
}

static void
start_and_stop_agent_with_slow_resolving (void)
{
  NiceAgent *agent = NULL;
  GThread *agent_thread = NULL;
  guint agent_closed, nresolvers, stream_id;
  GMainContext *close_context;
  gint64 before_close_ts, now_ts;

  /* sets up getaddrinfo() for blocking resolving of "bogus.nonexisting"
   * addresses */
  block_resolver_operations ();

  /* create a nice agent with one stream */
  agent_mainctxt = g_main_context_new ();
  agent_mainloop = g_main_loop_new (agent_mainctxt, FALSE);
  agent =
      nice_agent_new_full (agent_mainctxt, NICE_COMPATIBILITY_RFC5245,
      NICE_AGENT_OPTION_CLOSE_FORCED);
  stream_id = nice_agent_add_stream (agent, 1);

  /* trigger stun resolving */
  g_object_set (agent, "stun-server", "stun.bogus.nonexisting.com",
      "stun-server-port", 3478, NULL);
  g_assert_true (nice_agent_gather_candidates (agent, stream_id));

  /* trigger turn resolving */
  g_assert_true (nice_agent_set_relay_info (agent,
          stream_id,
          NICE_COMPONENT_TYPE_RTP,
          "turn.bogus.nonexisting.com", 3478, "user", "pass",
          NICE_RELAY_TYPE_TURN_UDP));

  /* run the agent main context in a separate thread */
  agent_thread = g_thread_new ("agent", agent_thread_cb, NULL);

  /* Wait until resolve tasks are in progress within getaddrinfo() */
  nresolvers = get_num_resolvers_in_progress ();
  while (nresolvers < 2) {
    g_thread_yield ();
    nresolvers = get_num_resolvers_in_progress ();
  }

  /* This section executes nice_agent_close_async() in a synchronous fashion,
   * which involves creating a GMainContext specifically for executing
   * nice_agent_close_async() and iterating the context until the completion
   * callback is invoked or a timeout occurs.
   *
   * This section is intended to serve as a template for how to use
   * nice_agent_close_async() synchronously in production code. */
  close_context = g_main_context_new ();
  agent_closed = 0;
  g_main_context_push_thread_default (close_context);
  before_close_ts = g_get_monotonic_time ();
  now_ts = before_close_ts;
  nice_agent_close_async (agent, agent_close_cb, &agent_closed);
  while (agent_closed != 1
      && (now_ts - before_close_ts) <= MAX_CLOSING_TIME_MICRO_SECONDS) {
    g_main_context_iteration (close_context, TRUE);
    now_ts = g_get_monotonic_time ();
  }
  g_main_context_pop_thread_default (close_context);
  g_main_context_unref (close_context);

  /* make sure all agents have swiftly closed down within MAX_CLOSING_TIME_MICRO_SECONDS */
  g_assert_cmpuint (agent_closed, ==, 1);

  /* stop the agent thread and release all resources */
  g_main_loop_quit (agent_mainloop);
  g_thread_join (agent_thread);
  g_object_unref (agent);
  g_main_loop_unref (agent_mainloop);
  g_main_context_unref (agent_mainctxt);

  /* stop blocking resolve operations in getaddrinfo(), let the ongoing resolve
   * operations finish and then reinstall the blocking */
  finish_resolver_operations ();
  nresolvers = get_num_resolvers_in_progress ();
  while (nresolvers != 0) {
    g_thread_yield ();
    nresolvers = get_num_resolvers_in_progress ();
  }

}

/* This test verifies that nice_agent_close_async() guarantees that after its
 * completion callback has been invoked it is safe to shut down the nice agent
 * thread without risk of leaking the agent GMainContext. Leaking the
 * GMainContext involves leaking an "eventfd" file descriptor and since the
 * number of open file descriptors is limited (typically 1024) the application
 * may quickly run out of file descriptors in the presence of a leak.
 *
 * The challenge mainly has to do with the way address resolution works in glib.
 * The asynchronous version of name lookup involves a worker thread and a pool
 * of threads to handle the underlying call to getaddrinfo(), which is a
 * synchronous call. There is a task related to the address lookup and that task
 * holds a reference to the agent GMainContext, which means the task has to
 * finish before the thread running the mainloop can be stopped.
 *
 * This test is pretty much a white-box test, i.e. we know the underlying glib
 * machinery is making use of getaddrinfo() and therefore we instrument
 * getaddrinfo() in this test (see slow-resolver.c). If the underlying machinery
 * changes, this test will have to be revisited. */
gint
main (int argc, char *argv[])
{
  gint i;
  guint nfd_before, nfd_after;

  /* Sanity check that we always have a number of open file descriptors */
  nfd_before = get_num_open_file_descriptors ();
  g_assert_cmpuint (nfd_before, >, 0);

  /* Start and stop the agent a 100 times to provoke leaking file descriptors. */
  for (i = 0; i < 100; ++i) {
    start_and_stop_agent_with_slow_resolving ();
  }

  /* When we have cancelled address resolution there will be some time before
   * the glib worker thread is run to free up the underlying task and its
   * associated main context, which in turn holds our "eventfd" file descriptor.
   * We cannot control this flow so just give it sufficient time to execute. */
  g_usleep (MAX_WAIT_FOR_RESOLVE_MICRO_SECONDS);

  /* If there is a file descriptor leak after shutting down the agent there will
   * be at least 100 leaked descriptors so the important thing to check is that
   * the current number of file descriptors is not in that area of magnitude.
   * Ideally we would like to have the same number of open file descriptors as
   * before, but glib implements a few allocations that always spans the
   * lifetime of the application. Adding a margin of 10 seems to be sufficient
   * for now. */
  nfd_after = get_num_open_file_descriptors ();
  g_assert_cmpuint (nfd_after, <, nfd_before + 10);

  return 0;
}
